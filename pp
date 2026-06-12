--liquibase formatted sql

--changeset adi_ajith:USP_reporting_purge_create labels:usp:reporting_purge splitStatements:false
--comment: Create USP_REPORTING_PURGE stored procedure

CREATE OR ALTER PROCEDURE dbo.USP_REPORTING_PURGE
    @status NVARCHAR(10) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @table_name NVARCHAR(128);
    DECLARE @sql        NVARCHAR(MAX);

    BEGIN TRY
        BEGIN TRANSACTION;

        DECLARE reporting_cursor CURSOR FOR
            SELECT table_name
            FROM dbo.SYS_PURGE_CONFIG
            WHERE layer = 'reporting'
              AND is_active = 1;

        OPEN reporting_cursor;
        FETCH NEXT FROM reporting_cursor INTO @table_name;

        WHILE @@FETCH_STATUS = 0
        BEGIN
            SET @sql = N'TRUNCATE TABLE ' + QUOTENAME(@table_name);
            EXEC sp_executesql @sql;

            UPDATE dbo.SYS_PURGE_CONFIG
            SET last_purged_date = GETDATE()
            WHERE table_name = @table_name
              AND layer = 'reporting';

            FETCH NEXT FROM reporting_cursor INTO @table_name;
        END;

        CLOSE reporting_cursor;
        DEALLOCATE reporting_cursor;

        COMMIT;
        SET @status = 'SUCCESS';

    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK;

        IF CURSOR_STATUS('local', 'reporting_cursor') >= 0
        BEGIN
            CLOSE reporting_cursor;
            DEALLOCATE reporting_cursor;
        END;

        SET @status = 'FAILED';
        THROW;
    END CATCH;
END;

--rollback IF OBJECT_ID('dbo.USP_REPORTING_PURGE', 'P') IS NOT NULL DROP PROCEDURE dbo.USP_REPORTING_PURGE;
