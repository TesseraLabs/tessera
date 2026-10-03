import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import core_compat_client as client


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.head = 'a' * 40
        self.base = 'b' * 40
        self.record = {'schema_version': 1, 'core_repo': client.CORE, 'core_pr': '3',
                       'core_sha': self.head, 'core_base_sha': self.base,
                       'enterprise_sha': 'c' * 40,
                       'scope': 'api-and-contract-smoke-not-native-package',
                       'status': 'success', 'signature_inputs_verified': True}

    def check(self, record):
        return client.validate_receipt(record, self.head, self.base, '3')

    def test_exact_receipt(self):
        self.assertEqual(self.check(self.record), self.record)

    def test_wrong_revision_or_scope(self):
        for key, value in [('core_sha', 'd' * 40), ('core_base_sha', 'd' * 40),
                           ('core_pr', '4'), ('core_repo', 'foreign/core'),
                           ('scope', 'native-package'), ('status', 'failed')]:
            record = copy.deepcopy(self.record); record[key] = value
            with self.assertRaises(ValueError): self.check(record)

    def test_unverified_and_non_boolean_signature_flag(self):
        for value in [False, 1, 'true']:
            record = copy.deepcopy(self.record); record['signature_inputs_verified'] = value
            with self.assertRaises(ValueError): self.check(record)

    def test_private_extra_data_refused(self):
        record = copy.deepcopy(self.record); record['private_diagnostics'] = 'not-public'
        with self.assertRaises(ValueError): self.check(record)

    def test_invalid_private_revision(self):
        record = copy.deepcopy(self.record); record['enterprise_sha'] = 'main'
        with self.assertRaises(ValueError): self.check(record)

    def test_untrusted_artifact_destination_refused_before_network(self):
        for url in ['http://storage.yandexcloud.net/a', 'https://evil.test/a',
                    'https://storage.yandexcloud.net.evil.test/a',
                    'https://user:secret@storage.yandexcloud.net/a',
                    'https://storage.yandexcloud.net:444/a']:
            with self.assertRaises(ValueError): client.read_receipt(url)
