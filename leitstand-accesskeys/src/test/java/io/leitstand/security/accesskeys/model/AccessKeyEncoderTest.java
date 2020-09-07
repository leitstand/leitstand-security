package io.leitstand.security.accesskeys.model;

import static io.leitstand.commons.model.StringUtil.toUtf8Bytes;
import static io.leitstand.security.auth.accesskeys.ReasonCode.AKY0101E_MALFORMED_ACCESSKEY;
import static io.leitstand.testing.ut.LeitstandCoreMatchers.reason;
import static java.util.Base64.getEncoder;

import java.util.Base64;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import io.leitstand.commons.AccessDeniedException;
import io.leitstand.commons.UnprocessableEntityException;
import io.leitstand.security.auth.accesskeys.AccessKeyEncodingService;

public class AccessKeyEncoderTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();
    
    private AccessKeyEncodingService service;
    
    @Before
    public void initTestEnvironment() {
        service = new AccessKeyEncodingService();
    }
    
    @Test
    public void report_invalid_base64_characters_as_malformed_token() {
        exception.expect(UnprocessableEntityException.class);
        exception.expect(reason(AKY0101E_MALFORMED_ACCESSKEY));
        service.decode("no:base:64");
    }
    
    @Test
    public void report_malformed_token() {
        exception.expect(AccessDeniedException.class);
        exception.expect(reason(AKY0101E_MALFORMED_ACCESSKEY));
        service.decode(getEncoder().encodeToString(toUtf8Bytes("malformed_token")));
    }
    
    @Test
    public void report_missing_signature_as_malformed_token() {
        exception.expect(AccessDeniedException.class);
        exception.expect(reason(AKY0101E_MALFORMED_ACCESSKEY));
        service.decode(getEncoder().encodeToString(toUtf8Bytes("no_signature:")));
    }
        
}
