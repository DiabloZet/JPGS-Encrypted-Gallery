# Локальная сборка: в этой папке выполнить  makepkg -si
pkgname=jpgs
pkgver=2.2.0
pkgrel=1
pkgdesc="Просмотр зашифрованных изображений .jpgs и видео .vids (GTK4, Wayland, libmpv/FFmpeg)"
arch=('any')
license=('MIT')
depends=('python' 'python-gobject' 'gtk4' 'libadwaita' 'openssl' 'mpv' 'python-av')
install=jpgs.install
optdepends=('python-cryptography: чуть более быстрая расшифровка (иначе используется OpenSSL напрямую)'
            'webp-pixbuf-loader: шифрование .webp'
            'python-nautilus: пункты в меню Nautilus')

package() {
    local src="$startdir"
    local bin=/usr/bin/jpgs
    local app=org.jpgs.JPGS

    install -d "$pkgdir/usr/lib/jpgs/jpgs"
    install -m644 "$src"/jpgs/*.py "$pkgdir/usr/lib/jpgs/jpgs/"
    python -m compileall -q -d /usr/lib/jpgs/jpgs "$pkgdir/usr/lib/jpgs/jpgs"

    install -Dm755 /dev/stdin "$pkgdir$bin" <<'EOS'
#!/bin/sh
PYTHONPATH="/usr/lib/jpgs${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m jpgs "$@"
EOS

    _subst() { install -Dm644 /dev/stdin "$2" < <(sed "s|@BIN@|$bin|g" "$1"); }
    _subst "$src/data/$app.desktop" "$pkgdir/usr/share/applications/$app.desktop"
    install -Dm644 "$src/data/jpgs-mime.xml" "$pkgdir/usr/share/mime/packages/jpgs.xml"
    _subst "$src/data/jpgs.thumbnailer" "$pkgdir/usr/share/thumbnailers/jpgs.thumbnailer"
    cp -r "$src/data/icons" "$pkgdir/usr/share/"
    find "$pkgdir/usr/share/icons" -type f -exec chmod 644 {} +
    for f in "$src"/integration/dolphin/*.desktop; do
        _subst "$f" "$pkgdir/usr/share/kio/servicemenus/$(basename "$f")"
    done
    _subst "$src/integration/nautilus/jpgs_nautilus.py" "$pkgdir/usr/share/nautilus-python/extensions/jpgs_nautilus.py"
    for f in "$src"/integration/nemo/*.nemo_action; do
        _subst "$f" "$pkgdir/usr/share/nemo/actions/$(basename "$f")"
    done
    install -Dm644 "$src/README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
    install -Dm644 "$src/LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
