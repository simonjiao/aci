from __future__ import annotations

import unittest
from io import BytesIO

from mcp_server.result_artifacts import _BoundedBinaryWriter, _ResultSizeLimitExceeded


class ResultArtifactTests(unittest.TestCase):
    def test_bounded_writer_rejects_a_write_before_exceeding_its_limit(self) -> None:
        target = BytesIO()
        writer = _BoundedBinaryWriter(target, 4)

        self.assertEqual(writer.write(b"1234"), 4)
        writer.seek(2)
        self.assertEqual(writer.write(b"ab"), 2)
        writer.seek(4)
        with self.assertRaises(_ResultSizeLimitExceeded):
            writer.write(b"5")

        self.assertEqual(target.getvalue(), b"12ab")


if __name__ == "__main__":
    unittest.main()
