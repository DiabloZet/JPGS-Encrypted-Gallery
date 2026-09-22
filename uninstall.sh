#!/bin/sh
# Удаление пользовательской установки JPGS (сделанной install.sh)
set -u
PREFIX="${PREFIX:-$HOME/.local}"
SHARE="${XDG_DATA_HOME:-$PREFIX/share}"
APP_ID="org.jpgs.JPGS"
rm -rf "$SHARE/jpgs"
rm -f "$PREFIX/bin/jpgs" "$SHARE/applications/$APP_ID.desktop" "$SHARE/mime/packages/jpgs.xml" \
      "$SHARE"/kio/servicemenus/jpgs-*.desktop "$SHARE/nautilus-python/extensions/jpgs_nautilus.py" \
      "$SHARE"/nemo/actions/jpgs-*.nemo_action "$SHARE/thumbnailers/jpgs.thumbnailer"
find "$SHARE/icons/hicolor" \( -name "$APP_ID.*" -o -name "application-x-jpgs.*" -o -name "application-x-vids.*" -o -name "jpgs-*-symbolic.svg" \) -delete 2>/dev/null
command -v update-mime-database >/dev/null && update-mime-database "$SHARE/mime" || true
command -v update-desktop-database >/dev/null && update-desktop-database -q "$SHARE/applications" || true
[ -f "${XDG_CONFIG_HOME:-$HOME/.config}/mimeapps.list" ] && sed -i "/^application\/x-\(jpgs\|vids\)=/d" "${XDG_CONFIG_HOME:-$HOME/.config}/mimeapps.list"
echo "JPGS удалён. Настройки остались в ~/.config/jpgs (удалите вручную при желании)."
