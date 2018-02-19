package com.exp;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;
import java.util.Properties;

@Configuration
@ComponentScan
public class DataSourceConfig {
    @Value("${spring.datasource.url}")
    private String dataSourceUrl;

    @Value("${spring.datasource.username}")
    private String userName;

    @Value("${spring.datasource.password}")
    private String password;

    @Value("${spring.datasource.dataSourceClassName}")
    private String dataSourceClassName;

    @Value("${spring.datasource.poolName}")
    private String poolName;

    @Value("${spring.datasource.connectionTimeout}")
    private Integer connectionTimeout;

    @Value("${spring.datasource.maxLifetime}")
    private Integer maxLifetime;

    @Value("${spring.datasource.maximumPoolSize}")
    private Integer maximumPoolSize;

    @Value("${spring.datasource.minimumIdle}")
    private Integer minimumIdle;

    @Value("${spring.datasource.idleTimeout}")
    private Integer idleTimeout;

    @Bean("primaryOauthDataSource")
    public DataSource primaryOauthDataSource() {
        Properties dsProps = new Properties();
        dsProps.put("url", dataSourceUrl);
        dsProps.put("user", userName);
        dsProps.put("password", password);
        dsProps.put("prepStmtCacheSize", 250);
        dsProps.put("prepStmtCacheSqlLimit", 2048);
        dsProps.put("cachePrepStmts", Boolean.TRUE);
        dsProps.put("useServerPrepStmts", Boolean.TRUE);

        Properties configProps = new Properties();
        configProps.put("dataSourceClassName", dataSourceClassName);
        configProps.put("poolName",poolName);
        configProps.put("maximumPoolSize",maximumPoolSize);
        configProps.put("minimumIdle",minimumIdle);
        configProps.put("connectionTimeout", connectionTimeout);
        configProps.put("idleTimeout", idleTimeout);
        configProps.put("dataSourceProperties", dsProps);

        HikariConfig hc = new HikariConfig(configProps);
        HikariDataSource ds = new HikariDataSource(hc);
        return ds;
    }

}

