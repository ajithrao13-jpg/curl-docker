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
--------------
@Repository
@Slf4j
public class ReportingPurgeRepository {

    private final SimpleJdbcCall simpleJdbcCall;

    public ReportingPurgeRepository(JdbcTemplate jdbcTemplate) {
        this.simpleJdbcCall = new SimpleJdbcCall(jdbcTemplate)
                .withSchemaName("dbo")
                .withProcedureName("USP_REPORTING_PURGE")
                .declareParameters(
                    new SqlOutParameter("status", Types.NVARCHAR)
                );
    }

    public String runReportingPurge() {
        log.info("Executing dbo.USP_REPORTING_PURGE");
        Map<String, Object> result = simpleJdbcCall
            .execute(new MapSqlParameterSource());
        return (String) result.get("status");
    }
}
--------
package com.mtb.cl7.databridge.service;

import com.mtb.cl7.databridge.repository.ReportingPurgeRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ReportingPurgeServiceTest {

    @Mock
    private ReportingPurgeRepository reportingPurgeRepository;

    @InjectMocks
    private ReportingPurgeService reportingPurgeService;

    @Test
    void runPurge_succeeds_whenStatusIsSuccess() {
        when(reportingPurgeRepository.runReportingPurge())
            .thenReturn("SUCCESS");

        assertThatNoException()
            .isThrownBy(() -> reportingPurgeService.runPurge());

        verify(reportingPurgeRepository, times(1))
            .runReportingPurge();
    }

    @Test
    void runPurge_throws_whenStatusIsFailed() {
        when(reportingPurgeRepository.runReportingPurge())
            .thenReturn("FAILED");

        assertThatThrownBy(() -> reportingPurgeService.runPurge())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("FAILED");
    }

    @Test
    void runPurge_throws_whenStatusIsNull() {
        when(reportingPurgeRepository.runReportingPurge())
            .thenReturn(null);

        assertThatThrownBy(() -> reportingPurgeService.runPurge())
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void runPurge_throws_whenRepositoryThrows() {
        when(reportingPurgeRepository.runReportingPurge())
            .thenThrow(new RuntimeException("DB connection failed"));

        assertThatThrownBy(() -> reportingPurgeService.runPurge())
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("DB connection failed");
    }
}
----------
package com.mtb.cl7.databridge.controller;

import com.mtb.cl7.databridge.service.ReportingPurgeService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(BlobIngestController.class)
class BlobIngestControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ReportingPurgeService reportingPurgeService;

    @Test
    @WithMockUser(authorities = "CL7.Admin")
    void triggerReportingPurge_returns200_whenSuccessful() throws Exception {
        doNothing().when(reportingPurgeService).runPurge();

        mockMvc.perform(post("/api/reporting_purge"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("success"))
            .andExpect(jsonPath("$.message")
                .value("Reporting purge job triggered"));

        verify(reportingPurgeService, times(1)).runPurge();
    }

    @Test
    @WithMockUser(authorities = "CL7.User")
    void triggerReportingPurge_returns200_forCL7User() throws Exception {
        doNothing().when(reportingPurgeService).runPurge();

        mockMvc.perform(post("/api/reporting_purge"))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "CL7.ReadOnly")
    void triggerReportingPurge_returns403_forUnauthorizedRole() throws Exception {
        mockMvc.perform(post("/api/reporting_purge"))
            .andExpect(status().isForbidden());
    }

    @Test
    void triggerReportingPurge_returns401_whenNotAuthenticated() throws Exception {
        mockMvc.perform(post("/api/reporting_purge"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(authorities = "CL7.Admin")
    void triggerReportingPurge_returns500_whenServiceThrows() throws Exception {
        doThrow(new IllegalStateException("Reporting purge failed with status: FAILED"))
            .when(reportingPurgeService).runPurge();

        mockMvc.perform(post("/api/reporting_purge"))
            .andExpect(status().isInternalServerError());
    }
}

---------
package com.mtb.cl7.databridge.repository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.SqlOutParameter;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;

import java.lang.reflect.Field;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ReportingPurgeRepositoryTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private SimpleJdbcCall simpleJdbcCall;

    private ReportingPurgeRepository repository;

    @BeforeEach
    void setUp() throws Exception {
        repository = new ReportingPurgeRepository(jdbcTemplate);
        // inject mock SimpleJdbcCall via reflection
        Field field = ReportingPurgeRepository.class
                .getDeclaredField("simpleJdbcCall");
        field.setAccessible(true);
        field.set(repository, simpleJdbcCall);
    }

    @Test
    void runReportingPurge_returnsSuccess_whenSpReturnsSuccess() {
        when(simpleJdbcCall.execute(any(MapSqlParameterSource.class)))
                .thenReturn(Map.of("status", "SUCCESS"));

        String result = repository.runReportingPurge();

        assertThat(result).isEqualTo("SUCCESS");
        verify(simpleJdbcCall, times(1))
                .execute(any(MapSqlParameterSource.class));
    }

    @Test
    void runReportingPurge_returnsFailed_whenSpReturnsFailed() {
        when(simpleJdbcCall.execute(any(MapSqlParameterSource.class)))
                .thenReturn(Map.of("status", "FAILED"));

        String result = repository.runReportingPurge();

        assertThat(result).isEqualTo("FAILED");
    }

    @Test
    void runReportingPurge_returnsNull_whenStatusKeyMissing() {
        when(simpleJdbcCall.execute(any(MapSqlParameterSource.class)))
                .thenReturn(Map.of());

        String result = repository.runReportingPurge();

        assertThat(result).isNull();
    }

    @Test
    void runReportingPurge_throwsRuntimeException_whenDbFails() {
        when(simpleJdbcCall.execute(any(MapSqlParameterSource.class)))
                .thenThrow(new RuntimeException("DB connection failed"));

        assertThatThrownBy(() -> repository.runReportingPurge())
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("DB connection failed");
    }
}
-----------
// ADD THIS MOCK at the top with the other @Mock fields
@Mock
private ReportingPurgeService reportingPurgeService;

// -------------------------------------------------------
// ADD THESE 3 TEST METHODS at the bottom of the class
// -------------------------------------------------------

@Test
@WithMockUser(authorities = {"CL7.Admin"})
void triggerReportingPurge_success() throws Exception {
    doNothing().when(reportingPurgeService).runPurge();

    mockMvc.perform(post("/api/reporting_purge")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("success"))
            .andExpect(jsonPath("$.message")
                    .value("Reporting purge job triggered"));

    verify(reportingPurgeService).runPurge();
}

@Test
@WithMockUser(authorities = {"CL7.User"})
void triggerReportingPurge_success_asCL7User() throws Exception {
    doNothing().when(reportingPurgeService).runPurge();

    mockMvc.perform(post("/api/reporting_purge")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("success"));

    verify(reportingPurgeService).runPurge();
}

@Test
@WithMockUser(authorities = {"CL7.Admin"})
void triggerReportingPurge_failure() throws Exception {
    doThrow(new IllegalStateException("Reporting purge failed with status: FAILED"))
            .when(reportingPurgeService).runPurge();

    mockMvc.perform(post("/api/reporting_purge")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("failure"))
            .andExpect(jsonPath("$.message")
                    .value("Reporting purge failed with status: FAILED"));

    verify(reportingPurgeService).runPurge();
}


---
/**

 * POST /api/reporting_purge

 * Triggers the USP_REPORTING_PURGE stored procedure to truncate

 * all reporting tables configured in dbo.SYS_PURGE_CONFIG (layer = 'reporting').

 * Intended to be called by Automic as part of the pipeline workflow.

 */



/**

 * Invokes the reporting purge stored procedure via the repository.

 * Throws IllegalStateException if the procedure does not return 'SUCCESS'.

 */



/**

 * Executes dbo.USP_REPORTING_PURGE via SimpleJdbcCall.

 * Returns the OUTPUT parameter 'status' from the stored procedure

 * ('SUCCESS' or 'FAILED').

 */
