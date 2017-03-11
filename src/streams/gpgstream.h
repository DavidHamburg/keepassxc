#ifndef GPGSTREAM_H
#define GPGSTREAM_H

#include "streams/LayeredStream.h"
#include "gpgme++/context.h"
#include "qgpgme/dataprovider.h"
#include <QIODevice>

class GpgStream : public LayeredStream
{
    Q_OBJECT

public:
    explicit GpgStream(QIODevice* baseDevice);
    //GpgStream(QIODevice* baseDevice, qint32 blockSize);
    ~GpgStream();
    bool open(QIODevice::OpenMode mode) override;
    bool reset() override;
    void close() override;

protected:
    qint64 readData(char* data, qint64 maxSize) override;
    qint64 writeData(const char* data, qint64 maxSize) override;

private:
    /// \internal d-pointer class.
    class Private;
    /// \internal d-pointer instance.
    Private* const d;
    bool m_hasUnwrittenData;
    void init();
    void keyList(QStringList& list, bool secretKeys, const QString& pattern);
    void flush();
    void writeDataToBaseDevice(QGpgME::QByteArrayDataProvider *dataProvider);
};

#endif // GPGSTREAM_H
