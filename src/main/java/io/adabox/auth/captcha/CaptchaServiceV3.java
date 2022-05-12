package io.adabox.auth.captcha;

import io.adabox.auth.captcha.error.ReCaptchaInvalidException;
import io.adabox.auth.captcha.error.ReCaptchaUnavailableException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;

import java.net.URI;

@Slf4j
@Service("captchaServiceV3")
public class CaptchaServiceV3 extends AbstractCaptchaService {

    public static final String CONNECT = "connect";
    
    @Override
    public void processResponse(String response, final String action) throws ReCaptchaInvalidException {
        securityCheck(response);
        final URI verifyUri = URI.create(String.format(RECAPTCHA_URL_TEMPLATE, getReCaptchaSecret(), response, getClientIP()));
        try {
            final GoogleResponse googleResponse = restTemplate.getForObject(verifyUri, GoogleResponse.class);
            log.debug("Google's response: {} ", googleResponse.toString());
            if (!googleResponse.isSuccess() || !googleResponse.getAction().equals(action) || googleResponse.getScore() < captchaSettings.getThreshold()) {
                if (googleResponse.hasClientError()) {
                    reCaptchaAttemptService.reCaptchaFailed(getClientIP());
                }
                throw new ReCaptchaInvalidException("reCaptcha was not successfully validated");
            }
        } catch (RestClientException rce) {
            throw new ReCaptchaUnavailableException("Registration unavailable at this time.  Please try again later.", rce);
        }
        reCaptchaAttemptService.reCaptchaSucceeded(getClientIP());
    } 
}
