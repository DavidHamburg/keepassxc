#include "gpgstream.h"
#include <gpgme++/context.h>
#include <gpgme++/data.h>
#include <gpgme++/decryptionresult.h>
#include <gpgme++/encryptionresult.h>
#include <gpgme++/key.h>
#include <gpgme++/keylistresult.h>
#include <qgpgme/dataprovider.h>

class GpgStream::Private
{
public:
    Private(QIODevice* baseDevice)
    {
        GpgME::initializeLibrary();
        ctx = GpgME::Context::createForProtocol(GpgME::OpenPGP);
        if (!ctx)
            qDebug("Failed to create the GpgME context for the OpenPGP protocol");
        p_baseDevice = baseDevice;
    }

    ~Private()
    {
        delete ctx;
    }

    GpgME::Error m_lastError;

    GpgME::Context* ctx;
    GpgME::Data m_data;
    QIODevice* p_baseDevice;
    GpgME::Key m_key;
};

GpgStream::GpgStream(QIODevice* baseDevice, GpgEncryptionKey key)
    : LayeredStream(baseDevice)
    , d(new Private(baseDevice))
    , m_encryptionKey(key)
{
    init();
}

GpgStream::~GpgStream()
{
    close();
}

void GpgStream::init()
{
    loadKey();
}

bool GpgStream::open(QIODevice::OpenMode mode)
{
    setOpenMode(mode);

    if (isWritable()) {
        d->ctx->setArmor(true);
    }

    if (isReadable()) {
        QGpgME::QByteArrayDataProvider dataProvider(d->p_baseDevice->readAll());
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
    if (isWritable() && m_hasUnwrittenData) {
        flush();
    }
    if (isReadable()) {
        d->m_data.seek(0, SEEK_SET);
    }

    return true;
}

void GpgStream::close()
{
    if (!isOpen()) {
        return;
    }
    if (isWritable()) {
        flush();
    }

    LayeredStream::close();
    QIODevice::close();
    setOpenMode(NotOpen);
}

void GpgStream::flush()
{
    if (d->ctx) {
        d->m_data.seek(0, SEEK_SET);
        QGpgME::QByteArrayDataProvider dataProvider{};
        GpgME::Data dcipher(&dataProvider);

        std::vector<GpgME::Key> v { d->m_key };
        d->m_lastError = d->ctx->encrypt(v, d->m_data, dcipher, GpgME::Context::AlwaysTrust).error();
        if (!d->m_lastError) {
            writeDataToBaseDevice(&dataProvider);
            m_hasUnwrittenData = false;
        } else {
            if (d->m_lastError.encodedError()) {
                setErrorString(QLatin1String("Failure while writing temporary file for file: '") +
                               QLatin1String(d->m_lastError.asString()) + QLatin1String("'"));
            }
        }
    }
}

void GpgStream::writeDataToBaseDevice(QGpgME::QByteArrayDataProvider* dataProvider)
{
    qint64 totalBytesWritten = 0;
    do {
        const qint64 bytesWritten = m_baseDevice->write(dataProvider->data(), dataProvider->data().size());
        if (bytesWritten == -1) {
            setErrorString(QT_TRANSLATE_NOOP("GpgStream", "Error writing to underlying device: ") + m_baseDevice->errorString());
            return;
        }
        totalBytesWritten += bytesWritten;
    } while (totalBytesWritten != dataProvider->data().size());
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

    m_hasUnwrittenData = true;
    return bytesWritten;
}

void GpgStream::loadKey()
{
    GpgME::Error error;
    auto keyId = m_encryptionKey.getKeyId().toStdString();
    auto fingerprint = keyId.c_str();
    d->m_key = d->ctx->key(fingerprint, error, true);
    if (error) {
        setErrorString("Unknown gpg key: " + m_encryptionKey.getKeyId());
    }
}
