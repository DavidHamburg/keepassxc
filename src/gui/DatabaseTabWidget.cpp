/*
 *  Copyright (C) 2011 Felix Geyer <debfx@fobos.de>
 *  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "DatabaseTabWidget.h"

#include <QFileInfo>
#include <QLockFile>
#include <QTabWidget>
#include <QPushButton>

#include "autotype/AutoType.h"
#include "core/Config.h"
#include "core/Global.h"
#include "core/Database.h"
#include "core/Group.h"
#include "core/Metadata.h"
#include "format/CsvExporter.h"
#include "gui/Clipboard.h"
#include "gui/DatabaseWidget.h"
#include "gui/DatabaseWidgetStateSync.h"
#include "gui/DragTabBar.h"
#include "gui/FileDialog.h"
#include "gui/MessageBox.h"
#include "gui/entry/EntryView.h"
#include "gui/group/GroupView.h"
#include "gui/UnlockDatabaseDialog.h"

DatabaseManagerStruct::DatabaseManagerStruct()
    : dbWidget(nullptr)
    , lockFile(nullptr)
    , saveToFilename(false)
    , modified(false)
    , readOnly(false)
{
}


const int DatabaseTabWidget::LastDatabasesCount = 5;

DatabaseTabWidget::DatabaseTabWidget(QWidget* parent)
    : QTabWidget(parent)
    , m_dbWidgetStateSync(new DatabaseWidgetStateSync(this))
{
    DragTabBar* tabBar = new DragTabBar(this);
    setTabBar(tabBar);
    setDocumentMode(true);

    connect(this, SIGNAL(tabCloseRequested(int)), SLOT(closeDatabase(int)));
    connect(this, SIGNAL(currentChanged(int)), SLOT(emitActivateDatabaseChanged()));
    connect(this, SIGNAL(activateDatabaseChanged(DatabaseWidget*)), m_dbWidgetStateSync, SLOT(setActive(DatabaseWidget*)));
    connect(autoType(), SIGNAL(globalShortcutTriggered()), SLOT(performGlobalAutoType()));
}

DatabaseTabWidget::~DatabaseTabWidget()
{
    QHashIterator<Database*, DatabaseManagerStruct> i(m_dbList);
    while (i.hasNext()) {
        i.next();
        deleteDatabase(i.key());
    }
}

void DatabaseTabWidget::toggleTabbar()
{
    if (count() > 1) {
        tabBar()->show();
    } else {
        tabBar()->hide();
    }
}

void DatabaseTabWidget::newDatabase()
{
    DatabaseManagerStruct dbStruct;
    Database* db = new Database();
    db->rootGroup()->setName(tr("Root"));
    dbStruct.dbWidget = new DatabaseWidget(db, this);
    
    CompositeKey emptyKey;
    db->setKey(emptyKey);

    insertDatabase(db, dbStruct);
    
    if (!saveDatabaseAs(db)) {
        closeDatabase(db);
        return;
    }

    dbStruct.dbWidget->switchToMasterKeyChange(true);
}

void DatabaseTabWidget::openDatabase()
{
    QString filter = QString("%1 (*.kdbx);;%2 (*)").arg(tr("KeePass 2 Database"), tr("All files"));
    QString fileName = fileDialog()->getOpenFileName(this, tr("Open database"), QString(),
                                                     filter);
    if (!fileName.isEmpty()) {
        openDatabase(fileName);
    }
}

void DatabaseTabWidget::openDatabase(const QString& fileName, const QString& pw,
                                     const QString& keyFile)
{
    QFileInfo fileInfo(fileName);
    QString canonicalFilePath = fileInfo.canonicalFilePath();
    if (canonicalFilePath.isEmpty()) {
        emit messageGlobal(tr("File not found!"), MessageWidget::Error);
        return;
    }


    QHashIterator<Database*, DatabaseManagerStruct> i(m_dbList);
    while (i.hasNext()) {
        i.next();
        if (i.value().canonicalFilePath == canonicalFilePath) {
            if (!i.value().dbWidget->dbHasKey() && !(pw.isNull() && keyFile.isEmpty())) {
                // If the database is locked and a pw or keyfile is provided, unlock it
                i.value().dbWidget->switchToOpenDatabase(i.value().filePath, pw, keyFile);
            } else {
                setCurrentIndex(databaseIndex(i.key()));
            }
            return;
        }
    }

    DatabaseManagerStruct dbStruct;

    // test if we can read/write or read the file
    QFile file(fileName);
    if (!file.open(QIODevice::ReadWrite)) {
        if (!file.open(QIODevice::ReadOnly)) {
            // can't open
            emit messageGlobal(
                tr("Unable to open the database.").append("\n").append(file.errorString()), MessageWidget::Error);
            return;
        }
        else {
            // can only open read-only
            dbStruct.readOnly = true;
        }
    }
    file.close();

    QLockFile* lockFile = new QLockFile(QString("%1/.%2.lock").arg(fileInfo.canonicalPath(), fileInfo.fileName()));
    lockFile->setStaleLockTime(0);

    if (!dbStruct.readOnly && !lockFile->tryLock()) {
        // for now silently ignore if we can't create a lock file
        // due to lack of permissions
        if (lockFile->error() != QLockFile::PermissionError) {
            QMessageBox msgBox;
            msgBox.setWindowTitle(tr("Database already opened"));
            msgBox.setText(tr("The database you are trying to open is locked by another instance of KeePassXC.\n\n"
                              "Do you want to open it anyway?"));
            msgBox.setIcon(QMessageBox::Question);
            msgBox.addButton(QMessageBox::Yes);
            msgBox.addButton(QMessageBox::No);
            auto readOnlyButton = msgBox.addButton(tr("Open read-only"), QMessageBox::NoRole);
            msgBox.setDefaultButton(readOnlyButton);
            msgBox.setEscapeButton(QMessageBox::No);
            auto result = msgBox.exec();

            if (msgBox.clickedButton() == readOnlyButton) {
                dbStruct.readOnly = true;
                delete lockFile;
                lockFile = nullptr;
            } else if (result == QMessageBox::Yes) {
                // take over the lock file if possible
                if (lockFile->removeStaleLockFile()) {
                    lockFile->tryLock();
                }
            } else {
                delete lockFile;
                return;
            }
        }
    }

    Database* db = new Database();
    dbStruct.dbWidget = new DatabaseWidget(db, this);
    dbStruct.lockFile = lockFile;
    dbStruct.saveToFilename = !dbStruct.readOnly;

    dbStruct.filePath = fileInfo.absoluteFilePath();
    dbStruct.canonicalFilePath = canonicalFilePath;
    dbStruct.fileName = fileInfo.fileName();

    insertDatabase(db, dbStruct);

    if (dbStruct.readOnly) {
        emit messageTab(tr("File opened in read only mode."), MessageWidget::Warning);
    }

    updateLastDatabases(dbStruct.filePath);

    if (!(pw.isNull() && keyFile.isEmpty())) {
        dbStruct.dbWidget->switchToOpenDatabase(dbStruct.filePath, pw, keyFile);
    }
    else {
        dbStruct.dbWidget->switchToOpenDatabase(dbStruct.filePath);
    }
    emit messageDismissGlobal();
}

void DatabaseTabWidget::importCsv()
{
    QString fileName = fileDialog()->getOpenFileName(this, tr("Open CSV file"), QString(),
            tr("CSV file") + " (*.csv);;" + tr("All files (*)"));

    if (fileName.isEmpty()) {
        return;
    }

    Database* db = new Database();
    DatabaseManagerStruct dbStruct;
    dbStruct.dbWidget = new DatabaseWidget(db, this);

    insertDatabase(db, dbStruct);
    dbStruct.dbWidget->switchToImportCsv(fileName);
}

void DatabaseTabWidget::mergeDatabase()
{
    QString filter = QString("%1 (*.kdbx);;%2 (*)").arg(tr("KeePass 2 Database"), tr("All files"));
    const QString fileName = fileDialog()->getOpenFileName(this, tr("Merge database"), QString(),
                                                       filter);
    if (!fileName.isEmpty()) {
        mergeDatabase(fileName);
    }
}

void DatabaseTabWidget::mergeDatabase(const QString& fileName)
{
    currentDatabaseWidget()->switchToOpenMergeDatabase(fileName);
}

void DatabaseTabWidget::importKeePass1Database()
{
    QString fileName = fileDialog()->getOpenFileName(this, tr("Open KeePass 1 database"), QString(),
            tr("KeePass 1 database") + " (*.kdb);;" + tr("All files (*)"));

    if (fileName.isEmpty()) {
        return;
    }

    Database* db = new Database();
    DatabaseManagerStruct dbStruct;
    dbStruct.dbWidget = new DatabaseWidget(db, this);
    dbStruct.dbWidget->databaseModified();
    dbStruct.modified = true;

    insertDatabase(db, dbStruct);

    dbStruct.dbWidget->switchToImportKeepass1(fileName);
}

bool DatabaseTabWidget::closeDatabase(Database* db)
{
    Q_ASSERT(db);

    const DatabaseManagerStruct& dbStruct = m_dbList.value(db);
    int index = databaseIndex(db);
    Q_ASSERT(index != -1);

    dbStruct.dbWidget->closeUnlockDialog();
    QString dbName = tabText(index);
    if (dbName.right(1) == "*") {
        dbName.chop(1);
    }
    if (dbStruct.dbWidget->isInEditMode() && db->hasKey() && dbStruct.dbWidget->isEditWidgetModified()) {
        QMessageBox::StandardButton result =
            MessageBox::question(
            this, tr("Close?"),
            tr("\"%1\" is in edit mode.\nDiscard changes and close anyway?").arg(dbName.toHtmlEscaped()),
            QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Cancel);
        if (result == QMessageBox::Cancel) {
            return false;
        }
    }
    if (dbStruct.modified) {
        if (config()->get("AutoSaveOnExit").toBool()) {
            if (!saveDatabase(db)) {
                return false;
            }
        } else if (dbStruct.dbWidget->currentMode() != DatabaseWidget::LockedMode) {
            QMessageBox::StandardButton result =
                MessageBox::question(
                this, tr("Save changes?"),
                tr("\"%1\" was modified.\nSave changes?").arg(dbName.toHtmlEscaped()),
                QMessageBox::Yes | QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Yes);
            if (result == QMessageBox::Yes) {
                if (!saveDatabase(db)) {
                    return false;
                }
            } else if (result == QMessageBox::Cancel) {
                return false;
            }
        }
    }

    deleteDatabase(db);

    return true;
}

void DatabaseTabWidget::deleteDatabase(Database* db)
{
    const DatabaseManagerStruct dbStruct = m_dbList.value(db);
    bool emitDatabaseWithFileClosed = dbStruct.saveToFilename;
    QString filePath = dbStruct.filePath;

    int index = databaseIndex(db);

    removeTab(index);
    toggleTabbar();
    m_dbList.remove(db);
    delete dbStruct.lockFile;
    delete dbStruct.dbWidget;
    delete db;

    if (emitDatabaseWithFileClosed) {
        emit databaseWithFileClosed(filePath);
    }
}

bool DatabaseTabWidget::closeAllDatabases()
{
    while (!m_dbList.isEmpty()) {
        if (!closeDatabase()) {
            return false;
        }
    }
    return true;
}

bool DatabaseTabWidget::saveDatabase(Database* db)
{
    DatabaseManagerStruct& dbStruct = m_dbList[db];

    if (dbStruct.dbWidget->currentMode() == DatabaseWidget::LockedMode) {
        // Never allow saving a locked database; it causes corruption
        // We return true since a save is not required
        return true;
    }

    if (dbStruct.saveToFilename) {
        dbStruct.dbWidget->blockAutoReload(true);
        QString errorMessage = db->saveToFile(dbStruct.canonicalFilePath);
        dbStruct.dbWidget->blockAutoReload(false);

        if (errorMessage.isEmpty()) {
            // successfully saved database file
            dbStruct.modified = false;
            dbStruct.dbWidget->databaseSaved();
            updateTabName(db);
            emit messageDismissTab();
            return true;
        } else {
            dbStruct.modified = true;
            updateTabName(db);
            emit messageTab(tr("Writing the database failed.").append("\n").append(errorMessage),
                            MessageWidget::Error);
            return false;
        }
    } else {
        return saveDatabaseAs(db);
    }
}

bool DatabaseTabWidget::saveDatabaseAs(Database* db)
{
    while (true) {
        DatabaseManagerStruct& dbStruct = m_dbList[db];
        QString oldFileName;
        if (dbStruct.saveToFilename) {
            oldFileName = dbStruct.filePath;
        } else {
            oldFileName = tr("Passwords").append(".kdbx");
        }
        QString fileName = fileDialog()->getSaveFileName(this, tr("Save database as"),
                                                        oldFileName, tr("KeePass 2 Database").append(" (*.kdbx)"),
                                                        nullptr, 0, "kdbx");
        if (!fileName.isEmpty()) {
            QFileInfo fileInfo(fileName);
            QString lockFilePath;
            if (fileInfo.exists()) {
                // returns empty string when file doesn't exist
                lockFilePath = fileInfo.canonicalPath();
            } else {
                lockFilePath = fileInfo.absolutePath();
            }
            QString lockFileName = QString("%1/.%2.lock").arg(lockFilePath, fileInfo.fileName());
            QScopedPointer<QLockFile> lockFile(new QLockFile(lockFileName));
            lockFile->setStaleLockTime(0);
            if (!lockFile->tryLock()) {
                // for now silently ignore if we can't create a lock file
                // due to lack of permissions
                if (lockFile->error() != QLockFile::PermissionError) {
                    QMessageBox::StandardButton result = MessageBox::question(this, tr("Save database as"),
                        tr("The database you are trying to save as is locked by another instance of KeePassXC.\n"
                        "Do you want to save it anyway?"),
                        QMessageBox::Yes | QMessageBox::No);

                    if (result == QMessageBox::No) {
                        return false;
                    } else {
                        // take over the lock file if possible
                        if (lockFile->removeStaleLockFile()) {
                            lockFile->tryLock();
                        }
                    }
                }
            }

            // setup variables so saveDatabase succeeds
            dbStruct.saveToFilename = true;
            dbStruct.canonicalFilePath = fileName;

            if (!saveDatabase(db)) {
                // failed to save, revert back
                dbStruct.saveToFilename = false;
                dbStruct.canonicalFilePath = oldFileName;
                continue;
            }

            // refresh fileinfo since the file didn't exist before
            fileInfo.refresh();

            dbStruct.modified = false;
            dbStruct.saveToFilename = true;
            dbStruct.readOnly = false;
            dbStruct.filePath = fileInfo.absoluteFilePath();
            dbStruct.canonicalFilePath = fileInfo.canonicalFilePath();
            dbStruct.fileName = fileInfo.fileName();
            dbStruct.dbWidget->updateFilename(dbStruct.filePath);
            delete dbStruct.lockFile;
            dbStruct.lockFile = lockFile.take();
            updateTabName(db);
            updateLastDatabases(dbStruct.filePath);
            return true;
        } else {
            return false;
        }
    }
}

bool DatabaseTabWidget::closeDatabase(int index)
{
    if (index == -1) {
        index = currentIndex();
    }

    setCurrentIndex(index);

    return closeDatabase(indexDatabase(index));
}

void DatabaseTabWidget::closeDatabaseFromSender()
{
    Q_ASSERT(sender());
    DatabaseWidget* dbWidget = static_cast<DatabaseWidget*>(sender());
    Database* db = databaseFromDatabaseWidget(dbWidget);
    int index = databaseIndex(db);
    setCurrentIndex(index);
    closeDatabase(db);
}

bool DatabaseTabWidget::saveDatabase(int index)
{
    if (index == -1) {
        index = currentIndex();
    }

    return saveDatabase(indexDatabase(index));
}

bool DatabaseTabWidget::saveDatabaseAs(int index)
{
    if (index == -1) {
        index = currentIndex();
    }

    return saveDatabaseAs(indexDatabase(index));
}

void DatabaseTabWidget::exportToCsv()
{
    Database* db = indexDatabase(currentIndex());
    if (!db) {
        Q_ASSERT(false);
        return;
    }

    QString fileName = fileDialog()->getSaveFileName(this, tr("Export database to CSV file"),
                                                     QString(), tr("CSV file").append(" (*.csv)"),
                                                     nullptr, 0, "csv");
    if (fileName.isEmpty()) {
        return;
    }

    CsvExporter csvExporter;
    if (!csvExporter.exportDatabase(fileName, db)) {
        emit messageGlobal(
            tr("Writing the CSV file failed.").append("\n")
            .append(csvExporter.errorString()), MessageWidget::Error);
    }
}

void DatabaseTabWidget::changeMasterKey()
{
    currentDatabaseWidget()->switchToMasterKeyChange();
}

void DatabaseTabWidget::changeDatabaseSettings()
{
    currentDatabaseWidget()->switchToDatabaseSettings();
}

bool DatabaseTabWidget::readOnly(int index)
{
    if (index == -1) {
        index = currentIndex();
    }

    return indexDatabaseManagerStruct(index).readOnly;
}

bool DatabaseTabWidget::isModified(int index)
{
    if (index == -1) {
        index = currentIndex();
    }

    return indexDatabaseManagerStruct(index).modified;
}

QString DatabaseTabWidget::databasePath(int index)
{
    if (index == -1) {
        index = currentIndex();
    }

    return indexDatabaseManagerStruct(index).filePath;
}


void DatabaseTabWidget::updateTabName(Database* db)
{
    int index = databaseIndex(db);
    Q_ASSERT(index != -1);

    const DatabaseManagerStruct& dbStruct = m_dbList.value(db);

    QString tabName;

    if (dbStruct.saveToFilename || dbStruct.readOnly) {
        if (db->metadata()->name().isEmpty()) {
            tabName = dbStruct.fileName;
        }
        else {
            tabName = db->metadata()->name();
        }

        setTabToolTip(index, dbStruct.filePath);
    }
    else {
        if (db->metadata()->name().isEmpty()) {
            tabName = tr("New database");
        }
        else {
            tabName = QString("%1 [%2]").arg(db->metadata()->name(), tr("New database"));
        }
    }

    if (dbStruct.dbWidget->currentMode() == DatabaseWidget::LockedMode) {
        tabName.append(QString(" [%1]").arg(tr("locked")));
    }

    if (dbStruct.modified) {
        tabName.append("*");
    }

    setTabText(index, tabName);
    emit tabNameChanged();
}

void DatabaseTabWidget::updateTabNameFromDbSender()
{
    Q_ASSERT(qobject_cast<Database*>(sender()));

    updateTabName(static_cast<Database*>(sender()));
}

void DatabaseTabWidget::updateTabNameFromDbWidgetSender()
{
    Q_ASSERT(qobject_cast<DatabaseWidget*>(sender()));
    Q_ASSERT(databaseFromDatabaseWidget(qobject_cast<DatabaseWidget*>(sender())));

    DatabaseWidget* dbWidget = static_cast<DatabaseWidget*>(sender());
    updateTabName(databaseFromDatabaseWidget(dbWidget));
}

int DatabaseTabWidget::databaseIndex(Database* db)
{
    QWidget* dbWidget = m_dbList.value(db).dbWidget;
    return indexOf(dbWidget);
}

Database* DatabaseTabWidget::indexDatabase(int index)
{
    QWidget* dbWidget = widget(index);

    QHashIterator<Database*, DatabaseManagerStruct> i(m_dbList);
    while (i.hasNext()) {
        i.next();
        if (i.value().dbWidget == dbWidget) {
            return i.key();
        }
    }

    return nullptr;
}

DatabaseManagerStruct DatabaseTabWidget::indexDatabaseManagerStruct(int index)
{
    QWidget* dbWidget = widget(index);

    QHashIterator<Database*, DatabaseManagerStruct> i(m_dbList);
    while (i.hasNext()) {
        i.next();
        if (i.value().dbWidget == dbWidget) {
            return i.value();
        }
    }

    return DatabaseManagerStruct();
}

Database* DatabaseTabWidget::databaseFromDatabaseWidget(DatabaseWidget* dbWidget)
{
    QHashIterator<Database*, DatabaseManagerStruct> i(m_dbList);
    while (i.hasNext()) {
        i.next();
        if (i.value().dbWidget == dbWidget) {
            return i.key();
        }
    }

    return nullptr;
}

void DatabaseTabWidget::insertDatabase(Database* db, const DatabaseManagerStruct& dbStruct)
{
    m_dbList.insert(db, dbStruct);

    addTab(dbStruct.dbWidget, "");
    toggleTabbar();
    updateTabName(db);
    int index = databaseIndex(db);
    setCurrentIndex(index);
    connectDatabase(db);
    connect(dbStruct.dbWidget, SIGNAL(closeRequest()), SLOT(closeDatabaseFromSender()));
    connect(dbStruct.dbWidget, SIGNAL(databaseChanged(Database*, bool)), SLOT(changeDatabase(Database*, bool)));
    connect(dbStruct.dbWidget, SIGNAL(unlockedDatabase()), SLOT(updateTabNameFromDbWidgetSender()));
    connect(dbStruct.dbWidget, SIGNAL(unlockedDatabase()), SLOT(emitDatabaseUnlockedFromDbWidgetSender()));
}

DatabaseWidget* DatabaseTabWidget::currentDatabaseWidget()
{
    Database* db = indexDatabase(currentIndex());
    if (db) {
        return m_dbList[db].dbWidget;
    }
    else {
        return nullptr;
    }
}

bool DatabaseTabWidget::hasLockableDatabases() const
{
    QHashIterator<Database*, DatabaseManagerStruct> i(m_dbList);
    while (i.hasNext()) {
        i.next();
        DatabaseWidget::Mode mode = i.value().dbWidget->currentMode();

        if ((mode == DatabaseWidget::ViewMode || mode == DatabaseWidget::EditMode)
                && i.value().dbWidget->dbHasKey()) {
            return true;
        }
    }

    return false;
}

void DatabaseTabWidget::lockDatabases()
{
    clipboard()->clearCopiedText();

    for (int i = 0; i < count(); i++) {
        DatabaseWidget* dbWidget = static_cast<DatabaseWidget*>(widget(i));
        Database* db = databaseFromDatabaseWidget(dbWidget);

        DatabaseWidget::Mode mode = dbWidget->currentMode();

        if ((mode != DatabaseWidget::ViewMode && mode != DatabaseWidget::EditMode)
                || !dbWidget->dbHasKey()) {
            continue;
        }

        // show the correct tab widget before we are asking questions about it
        setCurrentWidget(dbWidget);

        if (mode == DatabaseWidget::EditMode && dbWidget->isEditWidgetModified()) {
            QMessageBox::StandardButton result =
                MessageBox::question(
                    this, tr("Lock database"),
                    tr("Can't lock the database as you are currently editing it.\nPlease press cancel to finish your changes or discard them."),
                    QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Cancel);
            if (result == QMessageBox::Cancel) {
                continue;
            }
        }


        if (m_dbList[db].modified && !m_dbList[db].saveToFilename) {
            QMessageBox::StandardButton result =
                MessageBox::question(
                    this, tr("Lock database"),
                    tr("This database has never been saved.\nYou can save the database or stop locking it."),
                    QMessageBox::Save | QMessageBox::Cancel, QMessageBox::Cancel);
            if (result == QMessageBox::Save) {
                if (!saveDatabase(db)) {
                    continue;
                }
            }
            else if (result == QMessageBox::Cancel) {
                continue;
            }
        }
        else if (m_dbList[db].modified) {
            QMessageBox::StandardButton result =
                MessageBox::question(
                    this, tr("Lock database"),
                    tr("This database has been modified.\nDo you want to save the database before locking it?\nOtherwise your changes are lost."),
                    QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Cancel);
            if (result == QMessageBox::Save) {
                if (!saveDatabase(db)) {
                    continue;
                }
            }
            else if (result == QMessageBox::Discard) {
                m_dbList[db].modified = false;
                m_dbList[db].dbWidget->databaseSaved();
            }
            else if (result == QMessageBox::Cancel) {
                continue;
            }
        }

        dbWidget->lock();
        // database has changed so we can't use the db variable anymore
        updateTabName(dbWidget->database());

        emit databaseLocked(dbWidget);
    }
}

void DatabaseTabWidget::modified()
{
    Q_ASSERT(qobject_cast<Database*>(sender()));

    Database* db = static_cast<Database*>(sender());
    DatabaseManagerStruct& dbStruct = m_dbList[db];

    if (config()->get("AutoSaveAfterEveryChange").toBool() && dbStruct.saveToFilename) {
        saveDatabase(db);
        return;
    }

    if (!dbStruct.modified) {
        dbStruct.modified = true;
        dbStruct.dbWidget->databaseModified();
        updateTabName(db);
    }
}

void DatabaseTabWidget::updateLastDatabases(const QString& filename)
{
    if (!config()->get("RememberLastDatabases").toBool()) {
        config()->set("LastDatabases", QVariant());
    }
    else {
        QStringList lastDatabases = config()->get("LastDatabases", QVariant()).toStringList();
        lastDatabases.prepend(filename);
        lastDatabases.removeDuplicates();

        while (lastDatabases.count() > LastDatabasesCount) {
            lastDatabases.removeLast();
        }
        config()->set("LastDatabases", lastDatabases);
    }
}

void DatabaseTabWidget::changeDatabase(Database* newDb, bool unsavedChanges)
{
    Q_ASSERT(sender());
    Q_ASSERT(!m_dbList.contains(newDb));

    DatabaseWidget* dbWidget = static_cast<DatabaseWidget*>(sender());
    Database* oldDb = databaseFromDatabaseWidget(dbWidget);
    DatabaseManagerStruct dbStruct = m_dbList[oldDb];
    dbStruct.modified = unsavedChanges;
    m_dbList.remove(oldDb);
    m_dbList.insert(newDb, dbStruct);

    updateTabName(newDb);
    connectDatabase(newDb, oldDb);
}

void DatabaseTabWidget::emitActivateDatabaseChanged()
{
    emit activateDatabaseChanged(currentDatabaseWidget());
}

void DatabaseTabWidget::emitDatabaseUnlockedFromDbWidgetSender()
{
    emit databaseUnlocked(static_cast<DatabaseWidget*>(sender()));
}

void DatabaseTabWidget::connectDatabase(Database* newDb, Database* oldDb)
{
    if (oldDb) {
        oldDb->disconnect(this);
    }

    connect(newDb, SIGNAL(nameTextChanged()), SLOT(updateTabNameFromDbSender()));
    connect(newDb, SIGNAL(modified()), SLOT(modified()));
    newDb->setEmitModified(true);
}

void DatabaseTabWidget::performGlobalAutoType()
{
    QList<Database*> unlockedDatabases;

    QHashIterator<Database*, DatabaseManagerStruct> i(m_dbList);
    while (i.hasNext()) {
        i.next();
        DatabaseWidget::Mode mode = i.value().dbWidget->currentMode();

        if (mode != DatabaseWidget::LockedMode) {
            unlockedDatabases.append(i.key());
        }
    }

    if (unlockedDatabases.size() > 0) {
        autoType()->performGlobalAutoType(unlockedDatabases);
    } else if (m_dbList.size() > 0){
        indexDatabaseManagerStruct(0).dbWidget->showUnlockDialog();
    }
}
