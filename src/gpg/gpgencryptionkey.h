#ifndef GPGENCRYPTIONKEY_H
#define GPGENCRYPTIONKEY_H

#include <QString>
#include <string>

class GpgEncryptionKey
{
public:
    GpgEncryptionKey();
    GpgEncryptionKey(const char* fingerprint,
                     const char* shortKeyId,
                     const char* keyId,
                     const char* userId,
                     const char* subKeyId = nullptr);

    bool isNull() const
    {
        return m_keyId.isEmpty();
    }

    QString toString() const;
    QString getId() const
    {
        if (IsSubKey()) {
            return m_keyId + m_subKeyId;
        }
        return m_keyId;
    }
    QString getShortKeyId() const
    {
        return m_shortKeyId;
    }
    QString getKeyId() const
    {
        return m_keyId;
    }
    QString getFingerprint() const
    {
        return m_fingerprint;
    }
    QString getUserId() const
    {
        return m_userId;
    }
    QString getSubKeyId() const
    {
        return m_subKeyId;
    }
    bool IsSubKey() const
    {
        return m_isSubKey;
    }

private:
    QString m_fingerprint;
    QString m_shortKeyId;
    QString m_keyId;
    QString m_userId;
    bool m_isSubKey;
    QString m_subKeyId;
};

#endif // GPGENCRYPTIONKEY_H
