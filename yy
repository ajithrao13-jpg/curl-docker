CREATE OR ALTER PROCEDURE dbo.USP_TARGET_PURGE
    @status NVARCHAR(10) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @entity NVARCHAR(128);
    DECLARE @sql    NVARCHAR(MAX);

    BEGIN TRY
        BEGIN TRANSACTION;

        DECLARE entity_cursor CURSOR FOR
        SELECT table_name
        FROM dbo.SYS_PURGE_CONFIG
        WHERE layer = 'target'
          AND is_active = 1;

        OPEN entity_cursor;
        FETCH NEXT FROM entity_cursor INTO @entity;

        WHILE @@FETCH_STATUS = 0
        BEGIN
            SET @sql = N'
            DELETE ct
            FROM dbo.' + QUOTENAME(@entity) + ' ct
            INNER JOIN dbo.target pt ON ct.target_ID = pt.ID
            WHERE pt.status = ''sent''';

            EXEC sp_executesql @sql;

            -- Track successful purge for this table
            UPDATE dbo.SYS_PURGE_CONFIG
            SET last_purged_date = GETDATE()
            WHERE table_name = @entity
              AND layer = 'target';

            FETCH NEXT FROM entity_cursor INTO @entity;
        END;

        CLOSE entity_cursor;
        DEALLOCATE entity_cursor;

        -- Parent last (FK order)
        DELETE FROM dbo.target WHERE status = 'sent';

        COMMIT;
        SET @status = 'SUCCESS';

    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;
        IF CURSOR_STATUS('local', 'entity_cursor') >= 0
        BEGIN
            CLOSE entity_cursor;
            DEALLOCATE entity_cursor;
        END;
        SET @status = 'FAILED';
        THROW;
    END CATCH
END;

CREATE OR ALTER PROCEDURE dbo.STAGING_PURGE
    @status NVARCHAR(10) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @table_name     NVARCHAR(128);
    DECLARE @retention_days INT;
    DECLARE @sql            NVARCHAR(MAX);

    BEGIN TRY
        BEGIN TRANSACTION;

        DECLARE staging_cursor CURSOR FOR
            SELECT table_name, retention_days
            FROM dbo.SYS_PURGE_CONFIG
            WHERE layer = 'staging'
              AND is_active = 1
              AND retention_days IS NOT NULL
              AND (
                    last_purged_date IS NULL
                    OR CAST(last_purged_date AS DATE) < CAST(GETDATE() AS DATE)
                  );

        OPEN staging_cursor;
        FETCH NEXT FROM staging_cursor INTO @table_name, @retention_days;

        WHILE @@FETCH_STATUS = 0
        BEGIN
            SET @sql = N'
            DELETE FROM ' + QUOTENAME(@table_name) + '
            WHERE batch_date < DATEADD(DAY, -@days, CAST(GETDATE() AS DATE))';

            EXEC sp_executesql
                @sql,
                N'@days INT',
                @days = @retention_days;

            UPDATE dbo.SYS_PURGE_CONFIG
            SET last_purged_date = GETDATE()
            WHERE table_name = @table_name
              AND layer = 'staging';

            FETCH NEXT FROM staging_cursor INTO @table_name, @retention_days;
        END;

        CLOSE staging_cursor;
        DEALLOCATE staging_cursor;

        COMMIT;
        SET @status = 'SUCCESS';  -- only set if everything completed cleanly

    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;

        IF CURSOR_STATUS('local', 'staging_cursor') >= 0
        BEGIN
            CLOSE staging_cursor;
            DEALLOCATE staging_cursor;
        END;

        SET @status = 'FAILED';

        THROW;  -- rethrows original error back to Java

    END CATCH;

END;


CREATE TABLE dbo.SYS_PURGE_CONFIG
(
    config_id INT IDENTITY(1,1) PRIMARY KEY,
    table_name NVARCHAR(128) NOT NULL,
    layer NVARCHAR(20) NOT NULL, -- 'staging' / 'target' / 'raw'
    retention_days INT NULL,     -- only for staging
    is_active BIT NOT NULL DEFAULT 1,
    created_date DATETIME NOT NULL DEFAULT GETDATE(),
    last_purged_date DATETIME NULL,

    CONSTRAINT UQ_entity_config UNIQUE (table_name, layer)
);
