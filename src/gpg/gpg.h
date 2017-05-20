#ifndef GPG_H
#define GPG_H

#include "gpg/gpgencryptionkey.h"
#include <QStringList>
#include <vector>

class Gpg
{
public:
    Gpg();
    ~Gpg();
    void getAvailableSecretKeys(std::vector<GpgEncryptionKey>& list);
    const GpgEncryptionKey getKeyById(const QString id);

private:
    class Private;
    Private* const d;
    void keyList(std::vector<GpgEncryptionKey>& list, const QString& pattern);
};

#endif // GPG_H
