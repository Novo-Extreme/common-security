package br.com.vonex.common.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SalesChannelDTO {
    private Long id;
    private String code;
    private String name;
    private String description;
    private Boolean active;
}