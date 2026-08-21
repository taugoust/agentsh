//go:build !linux

package leakcheck

type resourceSnapshot struct{}

func prepareResourceTracking() error {
	return nil
}

func snapshotResources() (resourceSnapshot, error) {
	return resourceSnapshot{}, nil
}

func diffResources(resourceSnapshot, resourceSnapshot) []string {
	return nil
}
