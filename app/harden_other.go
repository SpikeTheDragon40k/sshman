//go:build !unix

package app

// HardenProcess is a no-op on this platform. Windows does not write core
// dumps by default; Windows Error Reporting settings are outside sshman.
func HardenProcess() {}
