"""SMTP protocol, credential boundaries, and delivery failure regressions."""
import smtplib
import socketserver
import ssl
import tempfile
import threading
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path
from unittest.mock import Mock, patch

from bridge.api.validation import FieldError
from bridge.features.notifications.channels import channels, destination, save_settings
from bridge.features.notifications.email import EMAIL_DEFAULTS, EmailDeliveryError, publish_email

ROOT = Path(__file__).resolve().parents[1]
CONFIG = {**EMAIL_DEFAULTS, 'emailEnabled': True, 'smtpHost': 'smtp.example.test',
          'smtpUsername': 'sender@example.test', 'smtpPassword': 'fixture-private-password',
          'emailFrom': 'sender@example.test', 'emailTo': 'recipient@example.test'}


class EmailTests(unittest.TestCase):
    def setUp(self):
        (ROOT/'.tmp').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT/'.tmp')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def test_password_retention_clear_and_server_identity_boundary(self):
        save_settings(self.directory, CONFIG)
        self.assertEqual(save_settings(self.directory, {'smtpPassword': ''})['smtpPassword'], CONFIG['smtpPassword'])
        for key, value in (('smtpHost', 'other.example.test'), ('smtpPort', 465), ('smtpSecurity', 'ssl'), ('smtpUsername', 'another')):
            with self.subTest(key=key), self.assertRaises(FieldError):
                save_settings(self.directory, {key: value, 'smtpPassword': ''})
        config = save_settings(self.directory, {'emailEnabled': False, 'smtpHost': 'other.example.test'})
        self.assertEqual(config['smtpPassword'], '')
        save_settings(self.directory, CONFIG)
        self.assertEqual(save_settings(self.directory, {'emailEnabled': False, 'clearSmtpPassword': True})['smtpPassword'], '')

    def test_invalid_settings_and_header_injection_are_rejected(self):
        for update in ({'emailEnabled': 'yes'}, {'smtpPort': True}, {'smtpPort': 0}, {'smtpPort': 65536},
                       {'smtpSecurity': 'automatic'}, {'smtpHost': 'https://smtp.example.test'},
                       {'smtpHost': 'smtp.example.test\r\nAUTH'}, {'smtpPassword': 'x\ny'},
                       {'emailFrom': 'sender@example.test\r\nBcc: hidden@example.test'},
                       {'emailTo': 'recipient@example.test\n'}, {'emailTo': 'missing-at-sign'},
                       {'emailTo': 'a@example.test,,b@example.test'}, {'emailTo': None},
                       {'clearSmtpPassword': 'yes'}):
            with self.subTest(update=update), self.assertRaises(FieldError):
                save_settings(self.directory, {**CONFIG, **update})

    def test_recipients_are_normalized_and_destination_changes_are_isolated(self):
        config = save_settings(self.directory, {**CONFIG, 'emailTo': 'one@example.test, two@example.test,one@example.test'})
        self.assertEqual(config['emailTo'], 'one@example.test, two@example.test')
        target = channels(config)['email']
        self.assertNotIn(CONFIG['smtpPassword'], target)
        self.assertNotEqual(target, destination({**config, 'emailTo': 'other@example.test'}, 'email'))
        self.assertNotIn('email', channels({**config, 'emailEnabled': False}))

    def test_starttls_verifies_certificate_before_authentication(self):
        smtp = Mock()
        smtp.__enter__ = Mock(return_value=smtp)
        smtp.__exit__ = Mock(return_value=False)
        smtp.send_message.return_value = {}
        with patch('bridge.features.notifications.email.smtplib.SMTP', return_value=smtp):
            publish_email(CONFIG, '测试标题', '测试内容', 'https://gateway.example.test/')
        calls = [call[0] for call in smtp.method_calls]
        self.assertLess(calls.index('starttls'), calls.index('login'))
        context = smtp.starttls.call_args.kwargs['context']
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        message = smtp.send_message.call_args.args[0]
        self.assertEqual(str(message['Subject']), '测试标题')
        self.assertIn('https://gateway.example.test/', message.get_content())
        self.assertNotIn(CONFIG['smtpPassword'], message.as_string())

    def test_missing_starttls_never_sends_credentials_or_falls_back(self):
        smtp = Mock()
        smtp.__enter__ = Mock(return_value=smtp)
        smtp.__exit__ = Mock(return_value=False)
        smtp.starttls.side_effect = smtplib.SMTPNotSupportedError('fixture private server response')
        with patch('bridge.features.notifications.email.smtplib.SMTP', return_value=smtp), self.assertRaises(EmailDeliveryError) as result:
            publish_email(CONFIG, 'title', 'body')
        smtp.login.assert_not_called()
        smtp.send_message.assert_not_called()
        self.assertNotIn('private server response', str(result.exception))

    def test_confirmed_delivery_survives_quit_timeout_without_resending(self):
        smtp = Mock()
        smtp.send_message.return_value = {}
        smtp.quit.side_effect = TimeoutError('fixture private disconnect failure')
        with patch('bridge.features.notifications.email.smtplib.SMTP', return_value=smtp):
            publish_email(CONFIG, 'title', 'body')
        smtp.send_message.assert_called_once()
        smtp.quit.assert_called_once()
        smtp.close.assert_called_once()

    def test_tls_connection_and_authentication_errors_are_sanitized(self):
        for error in (ssl.SSLCertVerificationError('fixture-private-password'),
                      smtplib.SMTPAuthenticationError(535, b'fixture-private-password')):
            with self.subTest(error=type(error).__name__), patch('bridge.features.notifications.email.smtplib.SMTP_SSL', side_effect=error), self.assertRaises(EmailDeliveryError) as result:
                publish_email({**CONFIG, 'smtpSecurity': 'ssl', 'smtpPort': 465}, 'title', 'body')
            self.assertNotIn(CONFIG['smtpPassword'], str(result.exception))

    def test_ssl_uses_verified_context_and_reports_partial_rejection(self):
        smtp = Mock()
        smtp.__enter__ = Mock(return_value=smtp)
        smtp.__exit__ = Mock(return_value=False)
        smtp.send_message.return_value = {'bad@example.test': (550, b'private response')}
        with patch('bridge.features.notifications.email.smtplib.SMTP_SSL', return_value=smtp) as connect, self.assertRaises(EmailDeliveryError):
            publish_email({**CONFIG, 'smtpSecurity': 'ssl', 'smtpPort': 465}, 'title', 'body')
        self.assertTrue(connect.call_args.kwargs['context'].check_hostname)
        smtp.starttls.assert_not_called()

    def test_real_smtp_loopback_delivers_utf8_mime_and_envelope(self):
        records = []
        class Receiver(socketserver.StreamRequestHandler):
            def handle(self):
                self.wfile.write(b'220 isolated SMTP fixture\r\n')
                while line := self.rfile.readline():
                    command = line.split(b' ', 1)[0].strip().upper()
                    if command == b'DATA':
                        self.wfile.write(b'354 send data\r\n')
                        data = []
                        while (chunk := self.rfile.readline()) not in (b'.\r\n', b''):
                            data.append(chunk)
                        records.append(b''.join(data))
                        self.wfile.write(b'250 queued\r\n')
                    elif command == b'QUIT':
                        self.wfile.write(b'221 bye\r\n')
                        return
                    else:
                        self.wfile.write(b'250 fixture\r\n')
        with socketserver.TCPServer(('127.0.0.1', 0), Receiver) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                publish_email({**CONFIG, 'smtpHost': '127.0.0.1', 'smtpPort': server.server_address[1],
                               'smtpSecurity': 'none', 'smtpUsername': '', 'smtpPassword': ''},
                              '任务已完成', '请打开聊天查看。', 'https://gateway.example.test/?chat=one')
            finally:
                server.shutdown()
                thread.join(2)
        self.assertEqual(len(records), 1)
        message = BytesParser(policy=policy.default).parsebytes(records[0])
        self.assertEqual(message['Subject'], '任务已完成')
        self.assertEqual(message['To'], 'recipient@example.test')
        self.assertIn('请打开聊天查看。', message.get_content())
        self.assertIn('?chat=one', message.get_content())
