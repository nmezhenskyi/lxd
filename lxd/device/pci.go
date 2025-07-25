package device

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	deviceConfig "github.com/canonical/lxd/lxd/device/config"
	pcidev "github.com/canonical/lxd/lxd/device/pci"
	"github.com/canonical/lxd/lxd/instance"
	"github.com/canonical/lxd/lxd/instance/instancetype"
	"github.com/canonical/lxd/lxd/util"
	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/validate"
)

type pci struct {
	deviceCommon
}

// validateConfig checks the supplied config for correctness.
func (d *pci) validateConfig(instConf instance.ConfigReader) error {
	if !instanceSupported(instConf.Type(), instancetype.VM) {
		return ErrUnsupportedDevType
	}

	rules := map[string]func(string) error{
		// lxdmeta:generate(entities=device-pci; group=device-conf; key=address)
		//
		// ---
		//  type: string
		//  required: yes
		//  shortdesc: PCI address of the device
		"address": validate.IsPCIAddress,
	}

	err := d.config.Validate(rules)
	if err != nil {
		return fmt.Errorf("Failed to validate config: %w", err)
	}

	d.config["address"] = pcidev.NormaliseAddress(d.config["address"])

	return nil
}

// validateEnvironment checks if the PCI device is available.
func (d *pci) validateEnvironment() error {
	if d.inst.Type() == instancetype.VM && shared.IsTrue(d.inst.ExpandedConfig()["migration.stateful"]) {
		return errors.New("PCI devices cannot be used when migration.stateful is enabled")
	}

	return validatePCIDevice(d.config["address"])
}

// Start is run when the device is added to the instance.
func (d *pci) Start() (*deviceConfig.RunConfig, error) {
	err := d.validateEnvironment()
	if err != nil {
		return nil, fmt.Errorf("Failed to validate environment: %w", err)
	}

	runConf := deviceConfig.RunConfig{}
	saveData := make(map[string]string)

	// Make sure that vfio-pci is loaded.
	err = util.LoadModule("vfio-pci")
	if err != nil {
		return nil, fmt.Errorf("Error loading %q module: %w", "vfio-pci", err)
	}

	// Get PCI information about the device.
	pciAddress := d.config["address"]
	devicePath := filepath.Join("/sys/bus/pci/devices", pciAddress)
	pciDev, err := pcidev.ParseUeventFile(filepath.Join(devicePath, "uevent"))
	if err != nil {
		return nil, fmt.Errorf("Failed to get PCI device info for %q: %w", pciAddress, err)
	}

	saveData["last_state.pci.slot.name"] = pciDev.SlotName
	saveData["last_state.pci.driver"] = pciDev.Driver

	pciIOMMUGroup, err := pcidev.DeviceIOMMUGroup(saveData["last_state.pci.slot.name"])
	if err != nil {
		return nil, err
	}

	err = pcidev.DeviceDriverOverride(pciDev, "vfio-pci")
	if err != nil {
		return nil, fmt.Errorf("Failed to override IOMMU group driver: %w", err)
	}

	runConf.PCIDevice = append(runConf.PCIDevice,
		[]deviceConfig.RunConfigItem{
			{Key: "devName", Value: d.name},
			{Key: "pciSlotName", Value: saveData["last_state.pci.slot.name"]},
			{Key: "pciIOMMUGroup", Value: strconv.FormatUint(pciIOMMUGroup, 10)},
		}...)

	err = d.volatileSet(saveData)
	if err != nil {
		return nil, err
	}

	return &runConf, nil
}

// CanHotPlug returns whether the device can be managed whilst the instance is running.
func (d *pci) CanHotPlug() bool {
	return true
}

// Stop is run when the device is removed from the instance.
func (d *pci) Stop() (*deviceConfig.RunConfig, error) {
	runConf := deviceConfig.RunConfig{
		PostHooks: []func() error{d.postStop},
	}

	return &runConf, nil
}

// postStop is run after the device is removed from the instance.
func (d *pci) postStop() error {
	defer func() {
		_ = d.volatileSet(map[string]string{
			"last_state.pci.slot.name": "",
			"last_state.pci.driver":    "",
		})
	}()

	v := d.volatileGet()

	// Unbind from vfio-pci and bind back to host driver.
	if v["last_state.pci.slot.name"] != "" {
		pciDev := pcidev.Device{
			Driver:   "vfio-pci",
			SlotName: v["last_state.pci.slot.name"],
		}

		err := pcidev.DeviceDriverOverride(pciDev, v["last_state.pci.driver"])
		if err != nil {
			return err
		}
	}

	return nil
}
