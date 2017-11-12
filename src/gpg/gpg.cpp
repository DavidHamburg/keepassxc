#include "gpg.h"
#include <gpgme++/context.h>
#include <gpgme++/data.h>
#include <gpgme++/decryptionresult.h>
#include <gpgme++/encryptionresult.h>
#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>
#include <qgpgme/dataprovider.h>

class Gpg::Private
{
public:
    Private()
    {
        GpgME::initializeLibrary();
        m_ctx = GpgME::Context::createForProtocol(GpgME::OpenPGP);
        if (!m_ctx)
            qDebug("Failed to create the GpgME context for the OpenPGP protocol");
    }

    ~Private()
    {
        delete m_ctx;
    }

    GpgME::Context* m_ctx;
};

Gpg::Gpg()
    : d(new Private())
{
}

Gpg::~Gpg()
{
    delete d;
}

const GpgEncryptionKey Gpg::getKeyById(const QString id)
{
    std::vector<GpgEncryptionKey> list;
    getAvailableSecretKeys(list);

    for (auto& element : list) {
        if (element.getId() == id) {
            return element;
        }
    }

    return GpgEncryptionKey();
}

void Gpg::getAvailableSecretKeys(std::vector<GpgEncryptionKey>& list)
{
    keyList(list, "");
}

void Gpg::keyList(std::vector<GpgEncryptionKey>& list, const QString& pattern)
{
    list.clear();
    if (d->m_ctx && !d->m_ctx->startKeyListing(pattern.toUtf8().constData(), true)) {
        GpgME::Error error;
        for (;;) {
            GpgME::Key key;
            key = d->m_ctx->nextKey(error);
            if (error.encodedError() != GPG_ERR_NO_ERROR)
                break;

            std::vector<GpgME::UserID> userIDs = key.userIDs();
            std::vector<GpgME::Subkey> subkeys = key.subkeys();
            for (unsigned int i = 0; i < userIDs.size(); ++i) {
                if (subkeys.size() > 0) {
                    for (unsigned int j = 0; j < subkeys.size(); ++j) {
                        const GpgME::Subkey& skey = subkeys[j];
                        if ((skey.canEncrypt() && skey.isSecret()) &&
                            !(skey.isRevoked() || skey.isExpired() || skey.isInvalid() || skey.isDisabled())) {
                            auto keyDesc = GpgEncryptionKey(
                                key.primaryFingerprint(), key.shortKeyID(), key.keyID(), userIDs[i].id(), skey.keyID());
                            list.push_back(keyDesc);
                        }
                    }
                } else {
                    if ((key.canEncrypt() && key.hasSecret()) &&
                        !(key.isRevoked() || key.isExpired() || key.isInvalid() || key.isDisabled())) {
                        auto keyDesc =
                            GpgEncryptionKey(key.primaryFingerprint(), key.shortKeyID(), key.keyID(), userIDs[i].id());
                        list.push_back(keyDesc);
                    }
                }
            }
        }
        d->m_ctx->endKeyListing();
    }
}
