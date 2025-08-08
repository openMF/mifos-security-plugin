/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.fineract.plugins.zitadel.security.api.exception;

import org.apache.fineract.plugins.zitadel.security.api.response.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class UserExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Object>> handleValidationErrors(MethodArgumentNotValidException ex) {
        ApiResponse<Object> response = new ApiResponse<>();
        response.setStatus(400);

        FieldError error = ex.getBindingResult().getFieldErrors().get(0);
        String field = error.getField();
        String defaultMessage = error.getDefaultMessage();

        int fieldCode = getFieldCode(field);
        int causeCode = getCauseCode(defaultMessage);
        int internalCode = Integer.parseInt(fieldCode + "" + causeCode);

        response.setMsg(defaultMessage);
        response.setObject(new ErrorCodeResponse(internalCode));

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    private int getFieldCode(String field) {
        return switch (field) {
            case "username" -> 10;
            case "email" -> 20;
            case "givenName" -> 30;
            case "familyName" -> 40;
            case "password" -> 50;
            default -> 0;
        };
    }

    private int getCauseCode(String message) {
        if (message.contains("obligatorio") || message.contains("blank")) return 6;
        if (message.contains("formato válido")) return 4;
        return 0;
    }

    private record ErrorCodeResponse(int code) {}
}
