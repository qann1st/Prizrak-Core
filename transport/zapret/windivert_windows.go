//go:build windows

package zapret

import "github.com/metacubex/mihomo/transport/internal/windivert"

type windivertAddress = windivert.Address
type winDivert = windivert.Divert

func loadWinDivert() (*winDivert, error) { return windivert.Load() }
