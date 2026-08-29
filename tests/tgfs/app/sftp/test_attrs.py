import stat

from tgfs.app.sftp.attrs import dir_attrs, file_attrs, root_attrs


class TestDirAttrs:
    def test_converts_milliseconds_to_seconds(self):
        attrs = dir_attrs(created_ms=1_700_000_000_000, modified_ms=1_700_000_123_000, readonly=False)

        assert attrs.crtime == 1_700_000_000
        assert attrs.mtime == 1_700_000_123
        assert attrs.atime == 1_700_000_123

    def test_marks_the_entry_as_a_directory(self):
        attrs = dir_attrs(0, 0, readonly=False)

        assert attrs.permissions is not None
        assert stat.S_ISDIR(attrs.permissions)
        assert stat.S_IMODE(attrs.permissions) == 0o755
        assert attrs.size == 0

    def test_readonly_user_sees_no_write_bits(self):
        attrs = dir_attrs(0, 0, readonly=True)

        assert attrs.permissions is not None
        assert stat.S_IMODE(attrs.permissions) == 0o555


class TestFileAttrs:
    def test_marks_the_entry_as_a_regular_file(self):
        attrs = file_attrs(size=42, created_ms=0, modified_ms=0, readonly=False)

        assert attrs.permissions is not None
        assert stat.S_ISREG(attrs.permissions)
        assert stat.S_IMODE(attrs.permissions) == 0o644
        assert attrs.size == 42

    def test_readonly_user_sees_no_write_bits(self):
        attrs = file_attrs(size=1, created_ms=0, modified_ms=0, readonly=True)

        assert attrs.permissions is not None
        assert stat.S_IMODE(attrs.permissions) == 0o444

    def test_negative_size_is_reported_as_zero(self):
        assert file_attrs(size=-1, created_ms=0, modified_ms=0, readonly=False).size == 0


class TestRootAttrs:
    def test_is_a_directory(self):
        attrs = root_attrs(readonly=False)

        assert attrs.permissions is not None
        assert stat.S_ISDIR(attrs.permissions)
        assert attrs.mtime == 0
