package api

import (
	"testing"
)

func TestIsTransitionalSimpleStreamsURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "Ubuntu releases",
			url:  "https://cloud-images.ubuntu.com/releases/",
			want: true,
		},
		{
			name: "Ubuntu buildd releases",
			url:  "https://cloud-images.ubuntu.com/buildd/releases/",
			want: true,
		},
		{
			name: "Ubuntu daily",
			url:  "https://cloud-images.ubuntu.com/daily/",
			want: true,
		},
		{
			name: "LXD images",
			url:  "https://images.lxd.canonical.com/",
			want: true,
		},
		{
			name: "LXD images no trailing slash",
			url:  "https://images.lxd.canonical.com",
			want: true,
		},
		{
			name: "HTTP scheme rejected",
			url:  "http://cloud-images.ubuntu.com/releases/",
			want: false,
		},
		{
			name: "Unknown host rejected",
			url:  "https://example.com/releases/",
			want: false,
		},
		{
			name: "Empty string",
			url:  "",
			want: false,
		},
		{
			name: "Invalid URL",
			url:  "://not-a-url",
			want: false,
		},
		{
			name: "Case insensitive host",
			url:  "https://Cloud-Images.Ubuntu.Com/releases/",
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsTransitionalSimpleStreamsURL(tc.url)
			if got != tc.want {
				t.Errorf("IsTransitionalSimpleStreamsURL(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}

func TestTransitionalRegistryName(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "Ubuntu releases",
			url:  "https://cloud-images.ubuntu.com/releases/",
			want: "cloud-images.ubuntu.com-releases",
		},
		{
			name: "Ubuntu buildd releases",
			url:  "https://cloud-images.ubuntu.com/buildd/releases/",
			want: "cloud-images.ubuntu.com-buildd-releases",
		},
		{
			name: "LXD images with trailing slash",
			url:  "https://images.lxd.canonical.com/",
			want: "images.lxd.canonical.com",
		},
		{
			name: "LXD images without trailing slash",
			url:  "https://images.lxd.canonical.com",
			want: "images.lxd.canonical.com",
		},
		{
			name: "Case normalized",
			url:  "https://Cloud-Images.Ubuntu.Com/Releases/",
			want: "cloud-images.ubuntu.com-Releases",
		},
		{
			name: "Multiple path segments",
			url:  "https://cloud-images.ubuntu.com/a/b/c/",
			want: "cloud-images.ubuntu.com-a-b-c",
		},
		{
			name: "Empty string returns empty",
			url:  "",
			want: "",
		},
		{
			name: "No host returns empty",
			url:  "https://",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TransitionalRegistryName(tc.url)
			if got != tc.want {
				t.Errorf("TransitionalRegistryName(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}
