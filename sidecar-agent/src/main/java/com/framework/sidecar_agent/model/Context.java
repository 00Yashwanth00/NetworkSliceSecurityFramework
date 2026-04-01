package com.framework.sidecar_agent.model;

import lombok.Data;

@Data
public class Context {
    private String sliceId;
    private String ueId;
    private String guti;
    private Integer pduSessionId;
    private Integer teid;
    private String ipAddress;
}
