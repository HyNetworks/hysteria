package acl

import (
	"reflect"
	"testing"
)

func TestParseTextRules(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    []TextRule
		wantErr bool
	}{
		{
			name:    "empty",
			text:    "",
			want:    []TextRule{},
			wantErr: false,
		},
		{
			name: "ok",
			text: `
# just a comment
 # another comment
direct(1.1.1.1)
direct(8.8.8.0/24)
reject(all, udp/443) # inline comment
 reject(geoip:cn)
  reject(*.v2ex.com)
my_custom_outbound1(9.9.9.9,*,   8.8.8.8) # bebop
my_custom_outbound2(all)
`,
			want: []TextRule{
				{Outbound: "direct", Address: "1.1.1.1", LineNum: 4},
				{Outbound: "direct", Address: "8.8.8.0/24", LineNum: 5},
				{Outbound: "reject", Address: "all", ProtoPort: "udp/443", LineNum: 6},
				{Outbound: "reject", Address: "geoip:cn", LineNum: 7},
				{Outbound: "reject", Address: "*.v2ex.com", LineNum: 8},
				{Outbound: "my_custom_outbound1", Address: "9.9.9.9", ProtoPort: "*", HijackAddress: "8.8.8.8", LineNum: 9},
				{Outbound: "my_custom_outbound2", Address: "all", LineNum: 10},
			},
			wantErr: false,
		},
		{
			name: "hyphen in outbound name",
			text: `
New-turkey(geosite:cn)
us-west-1(all, udp/443)
`,
			want: []TextRule{
				{Outbound: "New-turkey", Address: "geosite:cn", LineNum: 2},
				{Outbound: "us-west-1", Address: "all", ProtoPort: "udp/443", LineNum: 3},
			},
			wantErr: false,
		},
		{
			name:    "fail 1",
			text:    `boom()`,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "fail 2",
			text:    `lol(1,1,1,1)`,
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTextRules(tt.text)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTextRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseTextRules() got = %v, want %v", got, tt.want)
			}
		})
	}
}
