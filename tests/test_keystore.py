"""Тесты хранилища ключей и перешифровки — без GTK (чистая логика)."""

import os
import tempfile
import unittest

from jpgs import container as C
from jpgs.crypto import Cipher, KeyLocked


class KeystoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        # переменные окружения с ключом (их ставят другие тесты) не должны подменять хранилище
        self._env = {k: os.environ.pop(k, None)
                     for k in ("JPGS_KEY", "JPGS_WORD", "XDG_RUNTIME_DIR")}
        os.environ["XDG_CONFIG_HOME"] = self.dir
        # свежий singleton на каждый тест
        import jpgs.keystore as K
        K._INSTANCE = None
        self.K = K

    def tearDown(self):
        self.K._INSTANCE = None
        os.environ.pop("XDG_CONFIG_HOME", None)
        os.environ.pop("XDG_RUNTIME_DIR", None)
        for k, v in self._env.items():
            if v is not None:
                os.environ[k] = v

    def ks(self):
        self.K._INSTANCE = None
        return self.K.get_keystore()

    def test_add_activate_and_configured_material(self):
        from jpgs.crypto import configured_material, derive_material
        ks = self.ks()
        self.assertFalse(ks.exists())
        ks.add("Первый", "keyone-1234567890", kind="derived")
        b = ks.add("Второй", "keytwo-abcdefghij", kind="derived")
        self.assertEqual(ks.active_material(), derive_material("keyone-1234567890"))
        ks.set_active(b)
        self.assertEqual(ks.active_material(), derive_material("keytwo-abcdefghij"))
        # configured_material идёт через хранилище
        self.assertEqual(configured_material(), derive_material("keytwo-abcdefghij"))

    def test_remove_reassigns_active(self):
        ks = self.ks()
        ks.add("A", "aaaaaaaaaaaaaaaa", kind="derived")
        b = ks.add("B", "bbbbbbbbbbbbbbbb", kind="derived")
        ks.set_active(b)
        ks.remove(b)
        from jpgs.crypto import derive_material
        self.assertEqual(ks.active_material(), derive_material("aaaaaaaaaaaaaaaa"))

    def test_password_lock_unlock(self):
        ks = self.ks()
        ks.add("A", "secret-key-123456", kind="derived")
        ks.set_password("hunter2hunter2")
        # перечитать с диска
        ks2 = self.ks()
        self.assertTrue(ks2.is_encrypted())
        self.assertTrue(ks2.is_locked())
        with self.assertRaises(KeyLocked):
            ks2.active_material()
        self.assertFalse(ks2.unlock("wrong"))
        self.assertTrue(ks2.unlock("hunter2hunter2"))
        from jpgs.crypto import derive_material
        self.assertEqual(ks2.active_material(), derive_material("secret-key-123456"))

    def test_password_removed_leaves_plaintext(self):
        ks = self.ks()
        ks.add("A", "secret-key-123456", kind="derived")
        ks.set_password("pw-pw-pw-pw-pw")
        ks.set_password(None)
        ks2 = self.ks()
        self.assertFalse(ks2.is_encrypted())
        from jpgs.crypto import derive_material
        self.assertEqual(ks2.active_material(), derive_material("secret-key-123456"))

    def test_password_deletes_legacy_plaintext(self):
        # старый ключевой файл не должен оставаться после установки пароля
        from jpgs.crypto import key_file
        ks = self.ks()
        ks.add("A", "secret-key-123456", kind="raw")
        self.assertTrue(os.path.exists(key_file()))  # raw-ключ зеркалируется без пароля
        ks.set_password("pw-pw-pw-pw-pw")
        self.assertFalse(os.path.exists(key_file()))

    def test_derived_key_is_not_mirrored_to_legacy(self):
        """Усиленный ключ нельзя зеркалить: старая версия взяла бы слово как ключ напрямую."""
        from jpgs.crypto import key_file
        ks = self.ks()
        ks.add("Старый", "secret-key-123456", kind="raw")
        self.assertTrue(os.path.exists(key_file()))
        new = ks.add("Новый", "secret-key-123456", activate=True)  # derived
        self.assertFalse(os.path.exists(key_file()))
        self.assertEqual(ks.active_id(), new)

    def test_legacy_migration_keeps_old_format(self):
        """Ключ из прежней версии обязан переехать как 'raw' — иначе старые файлы не открыть."""
        from jpgs.crypto import key_file, config_dir, key_bytes
        os.makedirs(config_dir(), exist_ok=True)
        with open(key_file(), "w") as f:
            f.write("legacykey-1234567\n")
        ks = self.ks()
        self.assertTrue(ks.exists())
        self.assertEqual(ks.active_key(), "legacykey-1234567")
        self.assertEqual(len(ks.entries()), 1)
        self.assertEqual(ks.entries()[0]["kind"], "raw")
        self.assertEqual(ks.active_material(), key_bytes("legacykey-1234567"))

    def test_new_keys_are_scrypt_by_default(self):
        from jpgs.crypto import derive_material, key_bytes, scrypt_material
        ks = self.ks()
        kid = ks.add("Слово", "мой кот")
        self.assertEqual(ks.entries()[0]["kind"], "scrypt")
        self.assertEqual(ks.material_by_id(kid), scrypt_material("мой кот"))
        self.assertNotEqual(ks.material_by_id(kid), derive_material("мой кот"))
        self.assertNotEqual(ks.material_by_id(kid), key_bytes("мой кот"))
        # слово усиленного ключа не хранится и не восстанавливается
        with self.assertRaises(Exception):
            ks.active_key()

    def test_derivation_is_deterministic_across_stores(self):
        """То же слово на другом компьютере даёт тот же ключ (соль фиксированная)."""
        from jpgs.crypto import scrypt_material
        ks = self.ks()
        a = ks.add("A", "одно и то же слово")
        mat_a = ks.material_by_id(a)
        other = tempfile.mkdtemp()
        os.environ["XDG_CONFIG_HOME"] = other
        ks2 = self.ks()
        b = ks2.add("B", "одно и то же слово")
        self.assertEqual(mat_a, ks2.material_by_id(b))
        self.assertEqual(mat_a, scrypt_material("одно и то же слово"))

    def test_upgrade_creates_derived_twin(self):
        ks = self.ks()
        old = ks.add("Старый", "мой кот", kind="raw")
        new = ks.upgrade(old)
        self.assertEqual(len(ks.entries()), 2)
        self.assertNotEqual(ks.material_by_id(old), ks.material_by_id(new))
        self.assertEqual(ks.active_id(), old)  # активный не меняется сам по себе
        with self.assertRaises(ValueError):    # усиливать усиленный нельзя
            ks.upgrade(new)

    def test_word_is_not_written_to_disk(self):
        """Слово не должно попадать в keystore.json ни в каком виде."""
        ks = self.ks()
        ks.add("DiabloZet", "СекретноеСлово2024")
        with open(self.K.keystore_file(), encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("СекретноеСлово2024", text)
        self.assertNotIn('"key"', text)
        self.assertIn('"material"', text)
        self.assertIn("DiabloZet", text)  # имя записи — не секрет

    def test_old_file_with_word_is_cleaned_on_load(self):
        """Файл из версий ≤2.4 со словом чистится при первой же загрузке, ключ сохраняется."""
        import json
        from jpgs.crypto import derive_material, config_dir
        os.makedirs(config_dir(), exist_ok=True)
        old_doc = {"version": 1, "active": "aaa", "keys": [
            {"id": "aaa", "name": "DiabloZet", "key": "DiabloZet", "kind": "derived",
             "material": derive_material("DiabloZet").hex()},
            {"id": "bbb", "name": "Старый", "key": "старое слово", "kind": "raw"},
        ]}
        with open(self.K.keystore_file(), "w", encoding="utf-8") as f:
            json.dump(old_doc, f, ensure_ascii=False)
        ks = self.ks()
        # ключи продолжают работать
        self.assertEqual(ks.material_by_id("aaa"), derive_material("DiabloZet"))
        from jpgs.crypto import key_bytes
        self.assertEqual(ks.material_by_id("bbb"), key_bytes("старое слово"))
        # а слова из файла исчезли
        with open(self.K.keystore_file(), encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn('"key"', text)
        self.assertNotIn("старое слово", text)

    def test_raw_word_still_recoverable_for_upgrade(self):
        """Для старого формата слово выводится из его же байтов — иначе усиление не сделать."""
        from jpgs.crypto import scrypt_material
        ks = self.ks()
        old = ks.add("Старый", "мойстарыйключ", kind="raw")
        self.assertEqual(ks.key_by_id(old), "мойстарыйключ")
        new = ks.upgrade(old)
        self.assertEqual(ks.material_by_id(new), scrypt_material("мойстарыйключ"))

    def test_password_uses_scrypt_and_old_pbkdf2_store_is_upgraded(self):
        import json
        ks = self.ks()
        ks.add("A", "secret-key-123456", kind="raw")
        ks.set_password("long-password-123")
        with open(self.K.keystore_file(), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["kdf"]["algo"], "scrypt")
        # хранилище прежней версии (PBKDF2) читается и переводится на scrypt
        old = self.K.PBKDF2_ITERS
        kdf = {"algo": "pbkdf2-sha256", "salt": "00" * 16, "iters": old}
        enc, mac = self.K._derive("старый-пароль", kdf)
        import hashlib
        import hmac as H
        iv = b"\x01" * 16
        payload = json.dumps({"active": "x", "keys": [
            {"id": "x", "name": "A", "kind": "raw", "material": (b"k" * 32).hex()}]}).encode()
        ct = self.K._cbc_encrypt(enc, iv, payload)
        doc = {"version": 1, "encrypted": True, "kdf": kdf, "iv": iv.hex(), "ct": ct.hex(),
               "mac": H.new(mac, iv + ct, hashlib.sha256).digest().hex()}
        with open(self.K.keystore_file(), "w", encoding="utf-8") as f:
            json.dump(doc, f)
        ks2 = self.ks()
        self.assertTrue(ks2.is_locked())
        self.assertTrue(ks2.unlock("старый-пароль"))
        self.assertEqual(ks2.active_material(), b"k" * 32)
        with open(self.K.keystore_file(), encoding="utf-8") as f:
            self.assertEqual(json.load(f)["kdf"]["algo"], "scrypt")
        ks3 = self.ks()
        self.assertTrue(ks3.unlock("старый-пароль"))
        self.assertEqual(ks3.active_material(), b"k" * 32)

    def _settings(self, minutes):
        import json
        from jpgs.crypto import config_dir
        os.makedirs(config_dir(), exist_ok=True)
        with open(os.path.join(config_dir(), "settings.json"), "w") as f:
            json.dump({"unlock_minutes": minutes}, f)

    def test_unlock_is_remembered_for_a_while(self):
        import json
        import time
        rt = tempfile.mkdtemp()
        os.chmod(rt, 0o700)
        os.environ["XDG_RUNTIME_DIR"] = rt
        ks = self.ks()
        ks.add("A", "secret-key-123456", kind="raw")
        ks.set_password("long-password-123")
        # по умолчанию не запоминается
        self.assertTrue(self.ks().is_locked())
        self._settings(15)
        ks = self.ks()
        self.assertTrue(ks.unlock("long-password-123"))
        cache = os.path.join(rt, "jpgs-unlock.json")
        with open(cache) as f:
            text = f.read()
        self.assertNotIn("long-password-123", text)  # сам пароль не хранится
        ks2 = self.ks()
        self.assertFalse(ks2.is_locked())
        self.assertEqual(ks2.active_material(), ks.active_material())
        # просрочено — снова пароль, файл кэша удаляется
        doc = json.loads(text)
        doc["expires"] = time.time() - 1
        with open(cache, "w") as f:
            json.dump(doc, f)
        self.assertTrue(self.ks().is_locked())
        self.assertFalse(os.path.exists(cache))
        # «заблокировать сейчас»
        ks = self.ks()
        ks.unlock("long-password-123")
        self.assertTrue(os.path.exists(cache))
        ks.lock()
        self.assertTrue(ks.is_locked())
        self.assertFalse(os.path.exists(cache))
        self.assertTrue(self.ks().is_locked())
        # смена пароля делает старый кэш недействительным
        ks = self.ks()
        ks.unlock("long-password-123")
        with open(cache) as f:
            stale = f.read()
        ks.set_password("another-password-9")
        with open(cache, "w") as f:
            f.write(stale)
        self.assertTrue(self.ks().is_locked())

    def test_unlock_cache_refuses_shared_runtime_dir(self):
        rt = tempfile.mkdtemp()
        os.chmod(rt, 0o777)
        os.environ["XDG_RUNTIME_DIR"] = rt
        self.assertFalse(self.K.unlock_cache_available())

    def test_broken_keystore_is_kept_not_overwritten(self):
        from jpgs.crypto import config_dir
        os.makedirs(config_dir(), exist_ok=True)
        with open(self.K.keystore_file(), "w") as f:
            f.write("{не json")
        ks = self.ks()
        ks.add("Новый", "secret-key-123456", kind="raw")
        broken = [n for n in os.listdir(config_dir()) if n.startswith("keystore.json.broken")]
        self.assertEqual(len(broken), 1)

    def test_duplicate_key_rejected(self):
        ks = self.ks()
        ks.add("A", "secret-key-123456", kind="raw")
        with self.assertRaises(ValueError):
            ks.add("B", "secret-key-123456", kind="raw")

    def test_upgrade_pbkdf2_needs_right_word(self):
        from jpgs.crypto import scrypt_material
        ks = self.ks()
        kid = ks.add("A", "верное слово ключа", kind="derived")
        with self.assertRaises(ValueError):
            ks.upgrade(kid)                      # слово не хранится
        with self.assertRaises(ValueError):
            ks.upgrade(kid, word="чужое слово")  # и чужое не подходит
        new = ks.upgrade(kid, word="верное слово ключа")
        self.assertEqual(ks.material_by_id(new), scrypt_material("верное слово ключа"))

    def test_keyring_has_all_keys(self):
        from jpgs.crypto import KeyRing
        ks = self.ks()
        a = ks.add("A", "secret-key-123456", kind="raw")
        b = ks.add("B", "secret-key-abcdef", kind="raw")
        ring = KeyRing.from_config()
        self.assertEqual(ring.active.material, ks.material_by_id(a))
        self.assertEqual({c.material for c in ring.ciphers},
                         {ks.material_by_id(a), ks.material_by_id(b)})

    def test_key_strength(self):
        from jpgs.crypto import key_strength
        for weak in ("123456", "qwertyuiop", "aaaaaaaaaaaaaa", "abcdefghijkl", "1234567890"):
            self.assertFalse(key_strength(weak)[0], weak)
        for ok in ("correct horse battery staple", "k3$Lm9!qPz-Xw", "Мой кот ест 3 рыбы!"):
            self.assertTrue(key_strength(ok)[0], ok)

    def test_material_cached_in_file(self):
        """PBKDF2 не должен пересчитываться при каждом запуске."""
        import json
        ks = self.ks()
        ks.add("A", "какое-то слово")
        with open(self.K.keystore_file(), encoding="utf-8") as f:
            doc = json.load(f)
        self.assertIn("material", doc["keys"][0])


class ReencryptTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.old = Cipher(key="oldkey-1234567890")
        self.new = Cipher(key="newkey-abcdefghij")

    def test_reencrypt_jpgs_preserves_frames(self):
        p = os.path.join(self.dir, "a.jpgs")
        f1, f2 = b"\xff\xd8\xff\xd9", b"\xff\xd8\xff\xd9\xff\xd9"
        with open(p, "wb") as f:
            f.write(self.old.encrypt(f1))
            f.write(self.old.encrypt(f2))
        before = [C.JpgsFile(p, self.old).read_image(i) for i in range(2)]
        C.reencrypt_jpgs(p, self.old, self.new)
        after = [C.JpgsFile(p, self.new).read_image(i) for i in range(2)]
        self.assertEqual(before, after)
        # старым ключом больше не читается как JPEG
        self.assertFalse(C.verify_media(p, self.old))
        self.assertTrue(C.verify_media(p, self.new))

    def test_reencrypt_vids_roundtrip(self):
        raw = os.urandom(2_500_000)
        v = os.path.join(self.dir, "v.vids")
        with open(v, "wb") as f:
            f.write(self.old.encrypt(raw))
        C.reencrypt_vids(v, self.old, self.new)
        with C.DecryptingReader(v, self.new) as r:
            self.assertEqual(r.read(0, r.size), raw)

    def test_migration_old_files_to_derived_key(self):
        """Полный сценарий: старые файлы + усиление ключа + перешифровка → открываются новым."""
        from jpgs.crypto import key_bytes, derive_material
        word = "мойстарыйключ"
        old = Cipher(material=key_bytes(word))        # как шифровала прежняя версия
        new = Cipher(material=derive_material(word))  # усиленный ключ из того же слова
        paths = []
        for n in ("a", "b"):
            p = os.path.join(self.dir, f"{n}.jpgs")
            with open(p, "wb") as f:
                f.write(old.encrypt(b"\xff\xd8\xff\xd9"))
            paths.append(p)
        for p in paths:
            self.assertTrue(C.verify_media(p, old))
            self.assertFalse(C.verify_media(p, new))
            C.reencrypt_media(p, old, new)
        for p in paths:
            self.assertTrue(C.verify_media(p, new))
            self.assertFalse(C.verify_media(p, old))
            self.assertEqual(C.JpgsFile(p, new).read_image(0), b"\xff\xd8\xff\xd9")

    def test_verify_media_rejects_wrong_key(self):
        p = os.path.join(self.dir, "b.jpgs")
        with open(p, "wb") as f:
            f.write(self.old.encrypt(b"\xff\xd8\xff\xd9"))
        self.assertTrue(C.verify_media(p, self.old))
        self.assertFalse(C.verify_media(p, self.new))


if __name__ == "__main__":
    unittest.main()
