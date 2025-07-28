$url = "https://example.com/payload.exe"; $key = 0x42; ($url.ToCharArray() | ForEach-Object { [byte]([int][char]$_ -bxor $key) }) -join ","
