package com.vendo.auth_service.adapter.code.out;

import com.vendo.auth_service.port.code.CodeGenerator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class CodeSixDigitGeneratorTest {

    @Test
    void generate_shouldAlwaysGenerateSixDigitNumber() {
        CodeGenerator codeGenerator = new CodeSixDigitGenerator();

        for (int i = 0; i < 100; i++) {
            String code = codeGenerator.generate();
            assertThat(code).hasSize(6).matches("[1-9]\\d{5}");
        }
    }

}
