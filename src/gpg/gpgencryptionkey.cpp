#include "gpgencryptionkey.h"

GpgEncryptionKey::GpgEncryptionKey()
    : m_fingerprint(QString()),
      m_shortKeyId(QString()),
      m_keyId(QString()),
      m_userId(QString()),
      m_isSubKey(false)
{
}

GpgEncryptionKey::GpgEncryptionKey(const char* fingerprint, const char* shortKeyId, const char* keyId, const char* userId, const char* subKeyId)
    : m_fingerprint(QString(fingerprint)),
      m_shortKeyId(QString(shortKeyId)),
      m_keyId(QString(keyId)),
      m_userId(QString(userId)),
      m_isSubKey(subKeyId)
{
    if (subKeyId) {
        m_subKeyId = QString(subKeyId);
    }
    else {
        m_subKeyId = QString();
    }
}

QString GpgEncryptionKey::toString() const
{
    if (m_isSubKey){
        return QString("%1:%2 (subkey:%3)")
                .arg(m_shortKeyId)
                .arg(m_userId)
                .arg(m_subKeyId);
    }
    return QString("%1:%2").arg(m_shortKeyId).arg(m_userId);
}
