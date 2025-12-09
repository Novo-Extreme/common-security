package br.com.vonex.common.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SalesSegmentDTO {
    private Long id;
    private Long salesChannelId;
    private String code;
    private String name;
    private String segmentType;
    private String description;
    private Boolean active;
    private Boolean isPrimary;
}