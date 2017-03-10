#include "gpgstream.h"
#include <gpgme++/context.h>
#include <gpgme++/encryptionresult.h>
#include <gpgme++/decryptionresult.h>
#include <gpgme++/keylistresult.h>
#include <gpgme++/key.h>
#include <gpgme++/data.h>
#include <qgpgme/dataprovider.h>

class GpgStream::Private
{
public:
    Private(QIODevice* baseDevice) {
        GpgME::initializeLibrary();
        ctx = GpgME::Context::createForProtocol(GpgME::OpenPGP);
        if (!ctx)
            qDebug("Failed to create the GpgME context for the OpenPGP protocol");
        std::shared_ptr<QIODevice> p(baseDevice);
        p_baseDevice = p;
    }

    ~Private() {
        delete ctx;
    }

    GpgME::Error m_lastError;

    GpgME::Context* ctx;
    GpgME::Data m_data;
    std::shared_ptr<QIODevice> p_baseDevice;

    std::vector< GpgME::Key > m_recipients;

    // the result set of the last key list job
    std::vector< GpgME::Key > m_keys;
};

GpgStream::GpgStream(QIODevice* baseDevice)
    : LayeredStream(baseDevice),
      d(new Private(baseDevice))
{
    init();
}

GpgStream::~GpgStream()
{
    close();
}

void GpgStream::init()
{
    // skip a possible leading 0x in the id
    QString cmp = "david.nerjes@mailbox.org";
    if (cmp.startsWith(QLatin1String("0x")))
        cmp = cmp.mid(2);

    QStringList keylist;
    keyList(keylist, false, cmp);

    if (d->m_keys.size() > 0)
        d->m_recipients.push_back(d->m_keys.front());

    //TODO DN check rc and ctx
    /*GpgME::initializeLibrary();
    bool rc = (GpgME::checkEngine(GpgME::OpenPGP) == 0);

    std::unique_ptr<GpgME::Context> ctx(GpgME::Context::createForProtocol(GpgME::OpenPGP));
    if (!ctx){

        //raiseError("Failed to create gpg context.");
    }*/
}

bool GpgStream::open(QIODevice::OpenMode mode)
{
    setOpenMode(mode);

    if (isWritable()) {
        d->ctx->setArmor(true);
    }

    if (isReadable()) {
        QGpgME::QIODeviceDataProvider dataProvider(d->p_baseDevice);
        GpgME::Data dcipher(&dataProvider);
        d->m_lastError = d->ctx->decrypt(dcipher, d->m_data).error();
        if (d->m_lastError.encodedError()) {
            qDebug("%s", d->m_lastError.asString());
            return EOF;
        }

        d->m_data.seek(0, SEEK_SET);
    }
    return true;
}

bool GpgStream::reset()
{
    close();
    return true;
}

void GpgStream::close()
{
    if (!isOpen()) {
        return;
    }

    if (!d->ctx)
        return;

    if (isWritable()) {
        d->m_data.seek(0, SEEK_SET);

        QGpgME::QByteArrayDataProvider dataProvider{};
        GpgME::Data dcipher(&dataProvider);
        d->m_lastError = d->ctx->encrypt(d->m_recipients, d->m_data, dcipher, GpgME::Context::AlwaysTrust).error();
        if (d->m_lastError) {
            if (d->m_lastError.encodedError()) {
                setErrorString(QLatin1String("Failure while writing temporary file for file: '") + QLatin1String(d->m_lastError.asString()) + QLatin1String("'"));
            }
        }

        qint64 totalBytesWritten = 0;
        do {
            const qint64 bytesWritten = m_baseDevice->write(dataProvider.data(), dataProvider.data().size());
            if (bytesWritten == -1) {
                //q->setErrorString(QT_TRANSLATE_NOOP("QtIOCompressor", "Error writing to underlying device: ") + device->errorString());
                setErrorString("test");
                return;
            }
            totalBytesWritten += bytesWritten;
        } while (totalBytesWritten != dataProvider.data().size());

        LayeredStream::close();
        QIODevice::close();
    }

    d->m_recipients.clear();
    //setOpenMode(NotOpen);
}

qint64 GpgStream::readData(char* data, qint64 maxlen)
{
    if (maxlen == 0)
        return 0;

    if (!isOpen())
        return EOF;
    if (!isReadable())
        return EOF;

    qint64 bytesRead = 0;
    while (maxlen) {
        qint64 len = 2 ^ 31;
        if (len > maxlen)
            len = maxlen;
        bytesRead += d->m_data.read(data, len);
        data = &data[len];
        maxlen -= len;
    }
    return bytesRead;
}

qint64 GpgStream::writeData(const char* data, qint64 maxlen)
{
    if (!isOpen())
        return EOF;

    if (!isWritable())
        return EOF;

    qint64 bytesWritten = 0;
    while (maxlen) {
        qint64 len = 2 ^ 31;
        if (len > maxlen)
            len = maxlen;
        bytesWritten += d->m_data.write(data, len);
        data = &data[len];
        maxlen -= len;
    }
    return bytesWritten;
}


void GpgStream::keyList(QStringList& list, bool secretKeys, const QString& pattern)
{
    d->m_keys.clear();
    list.clear();
    if (d->ctx && !d->ctx->startKeyListing(pattern.toUtf8().constData(), secretKeys)) {
        GpgME::Error error;
        for (;;) {
            GpgME::Key key;
            key = d->ctx->nextKey(error);
            if (error.encodedError() != GPG_ERR_NO_ERROR)
                break;

            bool needPushBack = true;

            std::vector<GpgME::UserID> userIDs = key.userIDs();
            std::vector<GpgME::Subkey> subkeys = key.subkeys();
            for (unsigned int i = 0; i < userIDs.size(); ++i) {
                if (subkeys.size() > 0) {
                    for (unsigned int j = 0; j < subkeys.size(); ++j) {
                        const GpgME::Subkey& skey = subkeys[j];

                        if (((skey.canEncrypt() && !secretKeys) || (skey.isSecret() && secretKeys))

                                &&  !(skey.isRevoked() || skey.isExpired() || skey.isInvalid()  || skey.isDisabled())) {
                            QString entry = QString("%1:%2").arg(key.shortKeyID()).arg(userIDs[i].id());
                            list += entry;
                            if (needPushBack) {
                                d->m_keys.push_back(key);
                                needPushBack = false;
                            }
                        } else {
                            // qDebug("Skip key '%s'", key.shortKeyID());
                        }
                    }
                } else {
                    // we have no subkey, so we operate on the main key
                    if (((key.canEncrypt() && !secretKeys) || (key.hasSecret() && secretKeys))
                            && !(key.isRevoked() || key.isExpired() || key.isInvalid()  || key.isDisabled())) {
                        QString entry = QString("%1:%2").arg(key.shortKeyID()).arg(userIDs[i].id());
                        list += entry;
                        if (needPushBack) {
                            d->m_keys.push_back(key);
                            needPushBack = false;
                        }
                    } else {
                        // qDebug("Skip key '%s'", key.shortKeyID());
                    }
                }
            }
        }
        d->ctx->endKeyListing();
    }
}
