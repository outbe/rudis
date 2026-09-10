/*
 * Thin ABI adapter around the exact-pinned Intel DCAP QVL.
 *
 * Rust never depends on Intel struct layout directly. This file is compiled
 * against the headers from libsgx-dcap-quote-verify-dev 1.26.100.1 and copies
 * only stable values into an Outbe-owned result structure.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sgx_dcap_quoteverify.h>

#ifdef OUTBE_QVL_TEST_TRACE
#include <unistd.h>

static void test_trace_marker(const char *marker, size_t marker_size) {
    ssize_t written = write(STDERR_FILENO, marker, marker_size);
    (void)written;
}

#define TEST_TRACE_MARKER(marker) test_trace_marker(marker, sizeof(marker) - 1)
#else
#define TEST_TRACE_MARKER(marker) ((void)0)
#endif

struct outbe_qvl_collateral_v1 {
    const uint8_t *pck_crl_issuer_chain;
    uint32_t pck_crl_issuer_chain_size;
    const uint8_t *root_ca_crl;
    uint32_t root_ca_crl_size;
    const uint8_t *pck_crl;
    uint32_t pck_crl_size;
    const uint8_t *tcb_info_issuer_chain;
    uint32_t tcb_info_issuer_chain_size;
    const uint8_t *tcb_info;
    uint32_t tcb_info_size;
    const uint8_t *qe_identity_issuer_chain;
    uint32_t qe_identity_issuer_chain_size;
    const uint8_t *qe_identity;
    uint32_t qe_identity_size;
};

struct outbe_qvl_result_v1 {
    uint32_t aggregate_status;
    uint32_t collateral_expiration_status;
    uint16_t supplemental_major_version;
    uint16_t supplemental_minor_version;
    int64_t earliest_issue_date;
    int64_t latest_issue_date;
    int64_t earliest_expiration_date;
    uint32_t tcb_evaluation_data_number;
    uint16_t pce_id;
    uint32_t tee_type;
    uint8_t sgx_type;
    int32_t dynamic_platform;
    int32_t cached_keys;
    int32_t smt_enabled;
    uint8_t advisory_ids[450];
    uint32_t qe_status;
    uint32_t qe_tcb_evaluation_data_number;
};

_Static_assert(sizeof(struct outbe_qvl_collateral_v1) == 112,
               "unexpected Outbe collateral ABI size");
_Static_assert(_Alignof(struct outbe_qvl_collateral_v1) == 8,
               "unexpected Outbe collateral ABI alignment");
_Static_assert(sizeof(struct outbe_qvl_result_v1) == 528,
               "unexpected Outbe result ABI size");
_Static_assert(_Alignof(struct outbe_qvl_result_v1) == 8,
               "unexpected Outbe result ABI alignment");
_Static_assert(offsetof(struct outbe_qvl_result_v1, earliest_issue_date) == 16,
               "unexpected Outbe result date offset");
_Static_assert(offsetof(struct outbe_qvl_result_v1, advisory_ids) == 68,
               "unexpected Outbe result advisory offset");
_Static_assert(offsetof(struct outbe_qvl_result_v1, qe_status) == 520,
               "unexpected Outbe result QE-status offset");
_Static_assert(sizeof(sgx_ql_qv_supplemental_t) == 672,
               "unexpected Intel QVL supplemental ABI");
_Static_assert(SGX_QL_QV_RESULT_OK == 0x0000,
               "unexpected Intel QVL OK value");
_Static_assert(SGX_QL_QV_RESULT_CONFIG_NEEDED == 0xA001,
               "unexpected Intel QVL CONFIG_NEEDED value");
_Static_assert(SGX_QL_QV_RESULT_OUT_OF_DATE == 0xA002,
               "unexpected Intel QVL OUT_OF_DATE value");
_Static_assert(SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED == 0xA003,
               "unexpected Intel QVL OUT_OF_DATE_CONFIG_NEEDED value");
_Static_assert(SGX_QL_QV_RESULT_INVALID_SIGNATURE == 0xA004,
               "unexpected Intel QVL INVALID_SIGNATURE value");
_Static_assert(SGX_QL_QV_RESULT_REVOKED == 0xA005,
               "unexpected Intel QVL REVOKED value");
_Static_assert(SGX_QL_QV_RESULT_UNSPECIFIED == 0xA006,
               "unexpected Intel QVL UNSPECIFIED value");
_Static_assert(SGX_QL_QV_RESULT_SW_HARDENING_NEEDED == 0xA007,
               "unexpected Intel QVL SW_HARDENING_NEEDED value");
_Static_assert(SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED == 0xA008,
               "unexpected Intel QVL CONFIG_AND_SW_HARDENING_NEEDED value");

enum outbe_qvl_wrapper_status {
    OUTBE_QVL_WRAPPER_OK = 0,
    OUTBE_QVL_WRAPPER_INVALID_PARAMETER = 1,
    OUTBE_QVL_WRAPPER_UNSUPPORTED_ABI = 2,
    OUTBE_QVL_WRAPPER_QVL_ERROR = 3,
};

static int has_invalid_component(const struct outbe_qvl_collateral_v1 *input) {
    return input->pck_crl_issuer_chain == NULL || input->pck_crl_issuer_chain_size == 0 ||
           input->root_ca_crl == NULL || input->root_ca_crl_size == 0 ||
           input->pck_crl == NULL || input->pck_crl_size == 0 ||
           input->tcb_info_issuer_chain == NULL ||
           input->tcb_info_issuer_chain_size == 0 || input->tcb_info == NULL ||
           input->tcb_info_size == 0 || input->qe_identity_issuer_chain == NULL ||
           input->qe_identity_issuer_chain_size == 0 || input->qe_identity == NULL ||
           input->qe_identity_size == 0;
}

int32_t outbe_qvl_verify_quote_v1(
    const uint8_t *quote,
    uint32_t quote_size,
    const struct outbe_qvl_collateral_v1 *input,
    int64_t expiration_check_date,
    struct outbe_qvl_result_v1 *output) {
    if (quote == NULL || quote_size == 0 || input == NULL || output == NULL ||
        has_invalid_component(input)) {
        return OUTBE_QVL_WRAPPER_INVALID_PARAMETER;
    }
    if (sizeof(time_t) != sizeof(int64_t)) {
        return OUTBE_QVL_WRAPPER_UNSUPPORTED_ABI;
    }

    memset(output, 0, sizeof(*output));

    sgx_ql_qve_collateral_t collateral = {
        .major_version = 3,
        .minor_version = 1,
        .tee_type = 0,
        .pck_crl_issuer_chain = (char *)input->pck_crl_issuer_chain,
        .pck_crl_issuer_chain_size = input->pck_crl_issuer_chain_size,
        .root_ca_crl = (char *)input->root_ca_crl,
        .root_ca_crl_size = input->root_ca_crl_size,
        .pck_crl = (char *)input->pck_crl,
        .pck_crl_size = input->pck_crl_size,
        .tcb_info_issuer_chain = (char *)input->tcb_info_issuer_chain,
        .tcb_info_issuer_chain_size = input->tcb_info_issuer_chain_size,
        .tcb_info = (char *)input->tcb_info,
        .tcb_info_size = input->tcb_info_size,
        .qe_identity_issuer_chain = (char *)input->qe_identity_issuer_chain,
        .qe_identity_issuer_chain_size = input->qe_identity_issuer_chain_size,
        .qe_identity = (char *)input->qe_identity,
        .qe_identity_size = input->qe_identity_size,
    };

    uint32_t supplemental_size = 0;
    TEST_TRACE_MARKER("OUTBE_QVL_BEGIN\n");
    quote3_error_t qvl_error = sgx_qv_get_quote_supplemental_data_size(&supplemental_size);
    if (qvl_error != SGX_QL_SUCCESS) {
        TEST_TRACE_MARKER("OUTBE_QVL_END\n");
        return OUTBE_QVL_WRAPPER_QVL_ERROR;
    }
    if (supplemental_size != sizeof(sgx_ql_qv_supplemental_t)) {
        TEST_TRACE_MARKER("OUTBE_QVL_END\n");
        return OUTBE_QVL_WRAPPER_UNSUPPORTED_ABI;
    }

    sgx_ql_qv_supplemental_t supplemental;
    memset(&supplemental, 0, sizeof(supplemental));
    sgx_ql_qv_result_t aggregate_status = SGX_QL_QV_RESULT_UNSPECIFIED;
    uint32_t collateral_expiration_status = UINT32_MAX;

    qvl_error = sgx_qv_verify_quote(
        quote,
        quote_size,
        &collateral,
        (time_t)expiration_check_date,
        &collateral_expiration_status,
        &aggregate_status,
        NULL,
        supplemental_size,
        (uint8_t *)&supplemental);
    TEST_TRACE_MARKER("OUTBE_QVL_END\n");

    output->aggregate_status = (uint32_t)aggregate_status;
    output->collateral_expiration_status = collateral_expiration_status;
    if (qvl_error != SGX_QL_SUCCESS) {
        return OUTBE_QVL_WRAPPER_QVL_ERROR;
    }

    output->supplemental_major_version = supplemental.major_version;
    output->supplemental_minor_version = supplemental.minor_version;
    output->earliest_issue_date = (int64_t)supplemental.earliest_issue_date;
    output->latest_issue_date = (int64_t)supplemental.latest_issue_date;
    output->earliest_expiration_date = (int64_t)supplemental.earliest_expiration_date;
    output->tcb_evaluation_data_number = supplemental.tcb_eval_ref_num;
    output->pce_id = supplemental.pce_id;
    output->tee_type = supplemental.tee_type;
    output->sgx_type = supplemental.sgx_type;
    output->dynamic_platform = (int32_t)supplemental.dynamic_platform;
    output->cached_keys = (int32_t)supplemental.cached_keys;
    output->smt_enabled = (int32_t)supplemental.smt_enabled;
    memcpy(output->advisory_ids, supplemental.sa_list, sizeof(output->advisory_ids));
    output->qe_status = (uint32_t)supplemental.qe_iden_status;
    output->qe_tcb_evaluation_data_number = supplemental.qe_iden_tcb_eval_ref_num;
    return OUTBE_QVL_WRAPPER_OK;
}
