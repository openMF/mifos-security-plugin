package org.apache.fineract.infrastructure.zitadel.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.*;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.*;
import org.springframework.http.*;
import java.util.*;


@Component
public class AppReadyListener {

    @Autowired
    ApiService apiService;


    @EventListener(ApplicationReadyEvent.class)
    public void afterStartup(){
        try{
            String response = apiService.afterStartup();
            System.out.println(response);
        }catch (Exception e){
            System.out.println(e);
        }
    }


}