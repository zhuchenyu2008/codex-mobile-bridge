"""SMTP delivery with verified TLS and credential-free public errors."""
import re
import smtplib
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from bridge.features.auth.tls import client_context


EMAIL_DEFAULTS = {
    'emailEnabled': False, 'smtpHost': '', 'smtpPort': 587,
    'smtpSecurity': 'starttls', 'smtpUsername': '', 'smtpPassword': '',
    'emailFrom': '', 'emailTo': '',
}


class EmailDeliveryError(RuntimeError):
    """Only fixed messages may cross the desktop IPC boundary."""


class EmailConfigError(ValueError):
    def __init__(self, message, field):
        super().__init__(message)
        self.field = field


def mailbox(value, field):
    if not isinstance(value, str) or not value.isascii() or len(value) > 320 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise EmailConfigError('邮箱地址格式不正确', field)
    try:
        address = Address(addr_spec=value)
        if not address.username or not address.domain or address.addr_spec != value:
            raise ValueError()
    except (ValueError, IndexError):
        raise EmailConfigError('邮箱地址格式不正确', field) from None
    return value


def recipients(value):
    if not isinstance(value, str) or len(value) > 6400 or '\r' in value or '\n' in value:
        raise EmailConfigError('收件邮箱格式不正确', 'email-to')
    rows = value.split(',')
    if not 1 <= len(rows) <= 20:
        raise EmailConfigError('最多填写 20 个收件邮箱，用英文逗号分隔', 'email-to')
    return list(dict.fromkeys(mailbox(row.strip(), 'email-to') for row in rows))


def merge_email_config(prior, value):
    result = {key: value.get(key, prior.get(key, default)) for key, default in EMAIL_DEFAULTS.items()}
    if not isinstance(result['emailEnabled'], bool):
        raise EmailConfigError('邮件通知开关格式不正确', 'email-enabled')
    host = result['smtpHost']
    if not isinstance(host, str) or len(host) > 253 or (host and not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host)):
        raise EmailConfigError('SMTP 服务器请填写主机名或 IPv4 地址', 'smtp-host')
    if type(result['smtpPort']) is not int or not 1 <= result['smtpPort'] <= 65535:
        raise EmailConfigError('SMTP 端口应为 1–65535', 'smtp-port')
    if result['smtpSecurity'] not in ('starttls', 'ssl', 'none'):
        raise EmailConfigError('SMTP 加密方式格式不正确', 'smtp-security')
    for key, field in (('smtpUsername', 'smtp-username'), ('smtpPassword', 'smtp-password')):
        text = result[key]
        if not isinstance(text, str) or len(text) > 2000 or any(ord(c) < 32 or ord(c) == 127 for c in text):
            raise EmailConfigError('SMTP 认证信息格式不正确', field)
    if 'clearSmtpPassword' in value and not isinstance(value['clearSmtpPassword'], bool):
        raise EmailConfigError('SMTP 密码清除标记格式不正确', 'clear-smtp-password')
    identity_changed = any(result[key] != prior.get(key, EMAIL_DEFAULTS[key]) for key in ('smtpHost', 'smtpPort', 'smtpSecurity', 'smtpUsername'))
    if value.get('clearSmtpPassword'):
        result['smtpPassword'] = ''
    elif not value.get('smtpPassword'):
        result['smtpPassword'] = '' if identity_changed else prior.get('smtpPassword', '')
    for key, field in (('emailFrom', 'email-from'), ('emailTo', 'email-to')):
        if not isinstance(result[key], str):
            raise EmailConfigError('邮箱地址格式不正确', field)
        if result[key]:
            result[key] = mailbox(result[key], field) if key == 'emailFrom' else ', '.join(recipients(result[key]))
    if result['emailEnabled']:
        for key, field in (('smtpHost', 'smtp-host'), ('emailFrom', 'email-from'), ('emailTo', 'email-to')):
            if not result[key]:
                raise EmailConfigError('开启邮件通知前请填写服务器、发件邮箱和收件邮箱', field)
        if result['smtpUsername'] and not result['smtpPassword']:
            raise EmailConfigError('请填写 SMTP 密码；更换服务器或账号后需重新填写', 'smtp-password')
    return result


def publish_email(config, title, body, click=''):
    # Tests use the same saved configuration and validation as real events.
    config = merge_email_config(config, {'emailEnabled': True})
    message = EmailMessage()
    message['From'] = config['emailFrom']
    message['To'] = config['emailTo']
    message['Subject'] = title.replace('\r', ' ').replace('\n', ' ')[:200]
    message['Date'] = formatdate(localtime=True)
    message['Message-ID'] = make_msgid()
    message.set_content(body + ('\n\n' + click if click else ''), charset='utf-8')
    try:
        security = config['smtpSecurity']
        options = {'host': config['smtpHost'], 'port': config['smtpPort'], 'timeout': 12}
        smtp = smtplib.SMTP_SSL(**options, context=client_context()) if security == 'ssl' else smtplib.SMTP(**options)
        with smtp:
            smtp.ehlo()
            if security == 'starttls':
                smtp.starttls(context=client_context())
                smtp.ehlo()
            if config['smtpUsername']:
                smtp.login(config['smtpUsername'], config['smtpPassword'])
            rejected = smtp.send_message(message, from_addr=config['emailFrom'], to_addrs=recipients(config['emailTo']))
            if rejected:
                raise EmailDeliveryError('部分收件邮箱被邮件服务器拒绝，请检查收件地址')
    except EmailDeliveryError:
        raise
    except smtplib.SMTPAuthenticationError:
        raise EmailDeliveryError('SMTP 认证失败，请检查账号和密码') from None
    except smtplib.SMTPNotSupportedError:
        raise EmailDeliveryError('邮件服务器不支持所选加密或认证方式，请检查 SMTP 配置') from None
    except Exception:
        raise EmailDeliveryError('邮件发送失败，请检查 SMTP 地址、端口、证书和网络') from None
