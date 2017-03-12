#ifndef GPGENCRYPTIONKEY_H
#define GPGENCRYPTIONKEY_H

#include <QString>
#include <string>

class GpgEncryptionKey
{
public:
    GpgEncryptionKey();
    GpgEncryptionKey(const char* fingerprint, const char* shortKeyId, const char* keyId, const char* userId, const char* subKeyId = nullptr);

    bool isNull() const
    {
        return m_keyId.isEmpty();
    }

    const QString toString();
    const QString getId() {
        if (IsSubKey()) {
            return m_keyId + m_subKeyId;
        }
        return m_keyId;
    }
    const QString getShortKeyId() { return m_shortKeyId; }
    const QString getKeyId() { return m_keyId; }
    const QString getFingerprint() { return m_fingerprint; }
    const QString getUserId() { return m_userId; }
    const QString getSubKeyId() { return m_subKeyId; }
    bool IsSubKey() { return m_isSubKey; }

private:
    QString m_shortKeyId;
    QString m_keyId;
    QString m_userId;
    QString m_subKeyId;
    QString m_fingerprint;
    bool m_isSubKey;
};

#endif // GPGENCRYPTIONKEY_H
