package cmd

import (
	"bytes"
	"testing"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestMasqueradeCongestionConfig(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want *server.CongestionConfig
		err  string
	}{
		{name: "omitted preserves default", yaml: "masquerade:\n  type: '404'"},
		{name: "explicit bbr defaults to standard", yaml: "masquerade:\n  congestion:\n    type: bbr", want: &server.CongestionConfig{Type: "bbr", BBRProfile: "standard"}},
		{name: "profile only defaults to bbr", yaml: "masquerade:\n  congestion:\n    bbrProfile: aggressive", want: &server.CongestionConfig{Type: "bbr", BBRProfile: "aggressive"}},
		{name: "normalizes case", yaml: "masquerade:\n  congestion:\n    type: BBR\n    bbrProfile: Conservative", want: &server.CongestionConfig{Type: "bbr", BBRProfile: "conservative"}},
		{name: "reno ignores profile", yaml: "masquerade:\n  congestion:\n    type: reno\n    bbrProfile: unused", want: &server.CongestionConfig{Type: "reno"}},
		{name: "invalid type", yaml: "masquerade:\n  congestion:\n    type: brutal", err: `invalid config: masquerade.congestion.type: unsupported congestion type "brutal"`},
		{name: "invalid profile", yaml: "masquerade:\n  congestion:\n    type: bbr\n    bbrProfile: turbo", err: `invalid config: masquerade.congestion.bbrProfile: unsupported BBR profile "turbo"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			require.NoError(t, v.ReadConfig(bytes.NewBufferString(tt.yaml)))
			var c serverConfig
			require.NoError(t, v.Unmarshal(&c))
			proxy := server.CongestionConfig{Type: "bbr", BBRProfile: "aggressive"}
			hyConfig := &server.Config{CongestionConfig: proxy}
			err := c.fillMasqHandler(hyConfig)
			if tt.err != "" {
				require.EqualError(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, hyConfig.MasqCongestionConfig)
			require.Equal(t, proxy, hyConfig.CongestionConfig)
		})
	}
}
