# Oneliners

## Locate App Store / Sideloaded / TestFlight apps with CFBundleDisplayName variants

```sh
find /var/containers/Bundle/Application -maxdepth 2 -type d -name "*.app" | while read app; do
        uuid=$(basename "$(dirname "$app")")
        plist="$app/Info.plist"
      
        plutil "$plist" 2>/dev/null | grep -E 'CFBundleDisplayName([^=]*)[[:space:]]*=' | while read -r line; do
          key=$(echo "$line" | sed -E 's/^[[:space:]]*([^=]+)[[:space:]]*=.*/\1/')
          value=$(echo "$line" | sed -E 's/.*=[[:space:]]*(.*);/\1/')
          echo "$key = $value" | tr -d '"'
        done
      
        echo "UUID: $uuid"
        echo "App Path: $app"
        echo
      done
```

>  Requires plutil (available from the Procursus repository). To add Procursus repo, add https://apt.procurs.us/ as a source. 
