CREATE TABLE IF NOT EXISTS `t_cves` (
  `s_md5`    TEXT(64),
  `s_src`    TEXT(32),
  `s_cves`   TEXT(128),
  `s_title`  TEXT(256),
  `s_time`   TEXT(20),
  `s_info`   TEXT(2048),
  `s_url`    TEXT(256),
  `s_level`  TEXT(16) DEFAULT ''
);

CREATE INDEX IF NOT EXISTS `idx_t_cves_src`  ON `t_cves` (`s_src`);
CREATE INDEX IF NOT EXISTS `idx_t_cves_time` ON `t_cves` (`s_time`);
