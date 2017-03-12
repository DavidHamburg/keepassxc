#include "gpgencryptionkey.h"
GpgEncryptionKey::GpgEncryptionKey() { }

GpgEncryptionKey::GpgEncryptionKey(const char* fingerprint, const char* shortKeyId, const char* keyId, const char* userId, const char* subKeyId)
{
    m_fingerprint = QString(fingerprint);
    m_shortKeyId = QString(shortKeyId);
    m_keyId = QString(keyId);
    m_userId = QString(userId);
    if (subKeyId) {
        m_isSubKey = true;
        m_subKeyId = QString(subKeyId);
    }
    else {
        m_isSubKey = false;
        m_subKeyId = QString();
    }
}

const QString GpgEncryptionKey::toString()
{
    if (m_isSubKey){
        return QString("%1:%2 (subkey:%3)")
                .arg(m_shortKeyId)
                .arg(m_userId)
                .arg(m_subKeyId);
    }
    return QString("%1:%2").arg(m_shortKeyId).arg(m_userId);
}
