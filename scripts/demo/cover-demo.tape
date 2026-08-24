# Reproducible README recording. The demo runs the real Cover binary against
# scripts/demo/upstream.go, a local echo service that makes no network calls.
Output assets/cover-demo.gif

Require bwrap
Require curl
Require go
Require jq
Require ss

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 25
Set Width 1200
Set Height 560
Set Padding 22
Set Margin 18
Set MarginFill "#11111b"
Set BorderRadius 12
Set WindowBar "Colorful"
Set WindowBarSize 34
Set Theme "Catppuccin Mocha"
Set Framerate 24
Set TypingSpeed 22ms

Sleep 1500ms
Type "cover-demo" Enter
Sleep 9s
