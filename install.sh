#!/bin/sh
# Установка JPGS для текущего пользователя (в ~/.local), без root.
# Для установки в систему через pacman: makepkg -si
set -eu

SRC="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
SHARE="${XDG_DATA_HOME:-$PREFIX/share}"
LIB="$SHARE/jpgs"
BIN="$PREFIX/bin/jpgs"
APP_ID="org.jpgs.JPGS"

echo "==> Проверка зависимостей"
if ! python3 -c "import gi; gi.require_version('Gtk','4.0'); gi.require_version('Adw','1'); from gi.repository import Gtk, Adw" 2>/dev/null; then
    echo "Не найдены GTK4 / libadwaita для Python. Установите:"
    echo "    sudo pacman -S --needed python python-gobject gtk4 libadwaita"
    exit 1
fi

if ! python3 -c "import ctypes.util, sys; sys.exit(0 if ctypes.util.find_library('mpv') else 1)" 2>/dev/null; then
    echo "   ⚠ Для видео нужна libmpv:   sudo pacman -S mpv"
fi
if ! python3 -c "import av" 2>/dev/null; then
    echo "   ⚠ Для миниатюр видео нужен PyAV (FFmpeg):   sudo pacman -S python-av"
fi

echo "==> Программа → $LIB"
rm -rf "$LIB"
mkdir -p "$LIB/jpgs" "$PREFIX/bin"
cp "$SRC"/jpgs/*.py "$LIB/jpgs/"
python3 -m compileall -q "$LIB/jpgs" || true

cat > "$BIN" <<EOS
#!/bin/sh
PYTHONPATH="$LIB\${PYTHONPATH:+:\$PYTHONPATH}" exec python3 -m jpgs "\$@"
EOS
chmod 755 "$BIN"

subst() { sed "s|@BIN@|$BIN|g" "$1" > "$2"; }

echo "==> Ярлык, тип файла .jpgs, значки"
mkdir -p "$SHARE/applications" "$SHARE/mime/packages" "$SHARE/icons"
subst "$SRC/data/$APP_ID.desktop" "$SHARE/applications/$APP_ID.desktop"
cp "$SRC/data/jpgs-mime.xml" "$SHARE/mime/packages/jpgs.xml"
cp -r "$SRC/data/icons/hicolor" "$SHARE/icons/"

echo "==> Миниатюры .jpgs в файловых менеджерах"
mkdir -p "$SHARE/thumbnailers"
subst "$SRC/data/jpgs.thumbnailer" "$SHARE/thumbnailers/jpgs.thumbnailer"
rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}"/thumbnails/fail/*   # забыть прошлые неудачные попытки

echo "==> Контекстное меню: Dolphin / Nautilus / Nemo"
mkdir -p "$SHARE/kio/servicemenus" "$SHARE/nautilus-python/extensions" "$SHARE/nemo/actions"
for f in "$SRC"/integration/dolphin/*.desktop; do
    dst="$SHARE/kio/servicemenus/$(basename "$f")"
    subst "$f" "$dst"
    chmod +x "$dst"   # Plasma 6 требует исполняемый бит у пользовательских service menu
done
subst "$SRC/integration/nautilus/jpgs_nautilus.py" "$SHARE/nautilus-python/extensions/jpgs_nautilus.py"
for f in "$SRC"/integration/nemo/*.nemo_action; do
    subst "$f" "$SHARE/nemo/actions/$(basename "$f")"
done

echo "==> Ключ шифрования"
if [ -n "${JPGS_KEY:-}" ] || [ -s "${XDG_CONFIG_HOME:-$HOME/.config}/jpgs/key" ]; then
    echo "   $("$BIN" key 2>/dev/null || echo "Ключ уже задан (~/.config/jpgs/key)")"
elif [ -t 0 ]; then
    echo "   Ключ нужен для шифрования и открытия файлов. Встроенного ключа нет."
    echo "   Если у вас уже есть зашифрованные файлы — введите тот же ключ, которым они созданы."
    printf "   1) ввести свой ключ   2) сгенерировать случайный   3) позже (спросит при первом запуске) [1]: "
    read -r choice
    case "$choice" in
        2) "$BIN" set-key --generate ;;
        3) echo "   Ключ можно задать позже: jpgs set-key" ;;
        *) "$BIN" set-key ;;
    esac
else
    echo "   Ключ не задан — задайте командой «jpgs set-key» или при первом запуске программы."
fi

echo "==> Обновление баз"
command -v update-mime-database >/dev/null && update-mime-database "$SHARE/mime" || true
command -v update-desktop-database >/dev/null && update-desktop-database -q "$SHARE/applications" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t "$SHARE/icons/hicolor" 2>/dev/null || true
command -v xdg-mime >/dev/null && xdg-mime default "$APP_ID.desktop" application/x-jpgs application/x-vids || true
command -v kbuildsycoca6 >/dev/null && kbuildsycoca6 >/dev/null 2>&1 || true

echo
echo "Готово. Команда: $BIN"
case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *) echo "Совет: добавьте $PREFIX/bin в PATH, чтобы запускать просто «jpgs»." ;;
esac
echo "KDE: если пункты меню не появились — systemctl --user restart plasma-plasmashell и перезапустите Dolphin."
