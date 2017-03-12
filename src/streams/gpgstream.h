#ifndef GPGSTREAM_H
#define GPGSTREAM_H

#include "streams/LayeredStream.h"
#include "gpgme++/context.h"
#include "qgpgme/dataprovider.h"
#include "gpg/gpgencryptionkey.h"
#include <QIODevice>

class GpgStream : public LayeredStream
{
    Q_OBJECT

public:
    explicit GpgStream(QIODevice* baseDevice, GpgEncryptionKey& key);
    ~GpgStream();
    bool open(QIODevice::OpenMode mode) override;
    bool reset() override;
    void close() override;

protected:
    qint64 readData(char* data, qint64 maxSize) override;
    qint64 writeData(const char* data, qint64 maxSize) override;

private:
    class Private;
    Private* const d;
    bool m_hasUnwrittenData;
    GpgEncryptionKey& m_encryptionKey;
    void init(GpgEncryptionKey& key);
    void loadKey(GpgEncryptionKey& key);
    void flush();
    void writeDataToBaseDevice(QGpgME::QByteArrayDataProvider *dataProvider);
    void keyList(std::vector<GpgME::Key>& list, GpgEncryptionKey& encKey);
};

#endif // GPGSTREAM_H
