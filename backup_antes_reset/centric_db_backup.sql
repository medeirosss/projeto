--
-- PostgreSQL database dump
--

\restrict LsZa6xDqrUBB4gCzFsxs49ZkUXbk5hcDdfbHsBO8AxaRhMis15G2TbuIBEfNeK2

-- Dumped from database version 16.13 (Debian 16.13-1.pgdg13+1)
-- Dumped by pg_dump version 16.13 (Debian 16.13-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alert_history; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.alert_history (
    id integer NOT NULL,
    alert_id integer,
    old_status integer,
    new_status integer,
    action text,
    changed_by character varying(255),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.alert_history OWNER TO centric_user;

--
-- Name: alert_history_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.alert_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.alert_history_id_seq OWNER TO centric_user;

--
-- Name: alert_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.alert_history_id_seq OWNED BY public.alert_history.id;


--
-- Name: alerts; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.alerts (
    id integer NOT NULL,
    alert_uuid character varying(100) DEFAULT (gen_random_uuid())::text NOT NULL,
    source_system character varying(100),
    event_number character varying(50),
    event_type character varying(100),
    event_type_text character varying(100),
    display_name text,
    username character varying(255),
    hostname character varying(255),
    ip_address character varying(100),
    mitre_tactic character varying(100),
    mitre_technique character varying(100),
    nist_control character varying(100),
    severity character varying(50),
    status integer DEFAULT 1,
    raw_payload jsonb,
    received_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    resolved_at timestamp without time zone,
    resolved_by character varying(255),
    resolution_method character varying(50),
    CONSTRAINT alerts_status_check CHECK ((status = ANY (ARRAY[1, 2, 3])))
);


ALTER TABLE public.alerts OWNER TO centric_user;

--
-- Name: alerts_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.alerts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.alerts_id_seq OWNER TO centric_user;

--
-- Name: alerts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.alerts_id_seq OWNED BY public.alerts.id;


--
-- Name: app_audit_log; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.app_audit_log (
    id integer NOT NULL,
    username character varying(255),
    action character varying(255),
    module character varying(100),
    details jsonb,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.app_audit_log OWNER TO centric_user;

--
-- Name: app_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.app_audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.app_audit_log_id_seq OWNER TO centric_user;

--
-- Name: app_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.app_audit_log_id_seq OWNED BY public.app_audit_log.id;


--
-- Name: app_settings; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.app_settings (
    id integer NOT NULL,
    module character varying(100) NOT NULL,
    setting_key character varying(150) NOT NULL,
    setting_value text,
    encrypted boolean DEFAULT false,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.app_settings OWNER TO centric_user;

--
-- Name: app_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.app_settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.app_settings_id_seq OWNER TO centric_user;

--
-- Name: app_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.app_settings_id_seq OWNED BY public.app_settings.id;


--
-- Name: auth_allowed_groups; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.auth_allowed_groups (
    id integer NOT NULL,
    group_name character varying(255) NOT NULL,
    role character varying(50) DEFAULT 'viewer'::character varying NOT NULL,
    enabled boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.auth_allowed_groups OWNER TO centric_user;

--
-- Name: auth_allowed_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.auth_allowed_groups_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.auth_allowed_groups_id_seq OWNER TO centric_user;

--
-- Name: auth_allowed_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.auth_allowed_groups_id_seq OWNED BY public.auth_allowed_groups.id;


--
-- Name: auth_allowed_users; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.auth_allowed_users (
    id integer NOT NULL,
    username character varying(255) NOT NULL,
    role character varying(50) DEFAULT 'viewer'::character varying NOT NULL,
    enabled boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.auth_allowed_users OWNER TO centric_user;

--
-- Name: auth_allowed_users_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.auth_allowed_users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.auth_allowed_users_id_seq OWNER TO centric_user;

--
-- Name: auth_allowed_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.auth_allowed_users_id_seq OWNED BY public.auth_allowed_users.id;


--
-- Name: auth_local_users; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.auth_local_users (
    id integer NOT NULL,
    username character varying(255) NOT NULL,
    password_hash text NOT NULL,
    role character varying(50) DEFAULT 'admin'::character varying NOT NULL,
    enabled boolean DEFAULT true,
    must_change_password boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.auth_local_users OWNER TO centric_user;

--
-- Name: auth_local_users_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.auth_local_users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.auth_local_users_id_seq OWNER TO centric_user;

--
-- Name: auth_local_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.auth_local_users_id_seq OWNED BY public.auth_local_users.id;


--
-- Name: auth_settings; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.auth_settings (
    id integer NOT NULL,
    ldap_server character varying(255) NOT NULL,
    ldap_port integer DEFAULT 389,
    use_ssl boolean DEFAULT false,
    domain_name character varying(255) NOT NULL,
    base_dn character varying(255),
    enabled boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.auth_settings OWNER TO centric_user;

--
-- Name: auth_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.auth_settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.auth_settings_id_seq OWNER TO centric_user;

--
-- Name: auth_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.auth_settings_id_seq OWNED BY public.auth_settings.id;


--
-- Name: license_status; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.license_status (
    id integer NOT NULL,
    license_id character varying(100),
    customer_id character varying(150),
    customer_name character varying(255),
    domain_name character varying(255),
    license_type character varying(50),
    license_mode character varying(50),
    expires_at date,
    status character varying(50) DEFAULT 'unknown'::character varying NOT NULL,
    status_message text,
    modules jsonb DEFAULT '{}'::jsonb,
    max_users integer,
    max_endpoints integer,
    last_validation_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    raw_license jsonb
);


ALTER TABLE public.license_status OWNER TO centric_user;

--
-- Name: license_status_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.license_status_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.license_status_id_seq OWNER TO centric_user;

--
-- Name: license_status_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.license_status_id_seq OWNED BY public.license_status.id;


--
-- Name: login_audit_log; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.login_audit_log (
    id integer NOT NULL,
    username character varying(255),
    source_ip character varying(100),
    login_result character varying(50),
    reason text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.login_audit_log OWNER TO centric_user;

--
-- Name: login_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.login_audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.login_audit_log_id_seq OWNER TO centric_user;

--
-- Name: login_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.login_audit_log_id_seq OWNED BY public.login_audit_log.id;


--
-- Name: playbook_executions; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.playbook_executions (
    id integer NOT NULL,
    alert_id integer,
    playbook_id integer,
    credential_id integer,
    target character varying(255),
    variables jsonb,
    status character varying(50) DEFAULT 'pending'::character varying,
    output text,
    error text,
    executed_by character varying(255),
    started_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    finished_at timestamp without time zone
);


ALTER TABLE public.playbook_executions OWNER TO centric_user;

--
-- Name: playbook_executions_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.playbook_executions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.playbook_executions_id_seq OWNER TO centric_user;

--
-- Name: playbook_executions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.playbook_executions_id_seq OWNED BY public.playbook_executions.id;


--
-- Name: playbooks; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.playbooks (
    id integer NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    script_type character varying(50) NOT NULL,
    script_content text NOT NULL,
    required_variables jsonb DEFAULT '[]'::jsonb,
    metadata jsonb DEFAULT '{}'::jsonb,
    enabled boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.playbooks OWNER TO centric_user;

--
-- Name: playbooks_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.playbooks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.playbooks_id_seq OWNER TO centric_user;

--
-- Name: playbooks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.playbooks_id_seq OWNED BY public.playbooks.id;


--
-- Name: report_files; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.report_files (
    id integer NOT NULL,
    file_name character varying(255) NOT NULL,
    label character varying(255),
    size_bytes integer DEFAULT 0,
    hostnames jsonb DEFAULT '[]'::jsonb NOT NULL,
    content bytea,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.report_files OWNER TO centric_user;

--
-- Name: report_files_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.report_files_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.report_files_id_seq OWNER TO centric_user;

--
-- Name: report_files_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.report_files_id_seq OWNED BY public.report_files.id;


--
-- Name: scan_compare_runs; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.scan_compare_runs (
    id integer NOT NULL,
    report_name character varying(100) DEFAULT 'Scans'::character varying NOT NULL,
    sources jsonb DEFAULT '{}'::jsonb NOT NULL,
    rows jsonb DEFAULT '[]'::jsonb NOT NULL,
    total integer DEFAULT 0 NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.scan_compare_runs OWNER TO centric_user;

--
-- Name: scan_compare_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.scan_compare_runs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.scan_compare_runs_id_seq OWNER TO centric_user;

--
-- Name: scan_compare_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.scan_compare_runs_id_seq OWNED BY public.scan_compare_runs.id;


--
-- Name: scan_snapshots; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.scan_snapshots (
    id integer NOT NULL,
    source character varying(50) NOT NULL,
    records jsonb DEFAULT '[]'::jsonb NOT NULL,
    record_count integer DEFAULT 0 NOT NULL,
    source_detail character varying(255),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.scan_snapshots OWNER TO centric_user;

--
-- Name: scan_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.scan_snapshots_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.scan_snapshots_id_seq OWNER TO centric_user;

--
-- Name: scan_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.scan_snapshots_id_seq OWNED BY public.scan_snapshots.id;


--
-- Name: stored_credentials; Type: TABLE; Schema: public; Owner: centric_user
--

CREATE TABLE public.stored_credentials (
    id integer NOT NULL,
    name character varying(150) NOT NULL,
    credential_type character varying(50) NOT NULL,
    username character varying(255),
    domain character varying(255),
    secret_encrypted text NOT NULL,
    description text,
    metadata jsonb DEFAULT '{}'::jsonb,
    enabled boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.stored_credentials OWNER TO centric_user;

--
-- Name: stored_credentials_id_seq; Type: SEQUENCE; Schema: public; Owner: centric_user
--

CREATE SEQUENCE public.stored_credentials_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.stored_credentials_id_seq OWNER TO centric_user;

--
-- Name: stored_credentials_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: centric_user
--

ALTER SEQUENCE public.stored_credentials_id_seq OWNED BY public.stored_credentials.id;


--
-- Name: alert_history id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.alert_history ALTER COLUMN id SET DEFAULT nextval('public.alert_history_id_seq'::regclass);


--
-- Name: alerts id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.alerts ALTER COLUMN id SET DEFAULT nextval('public.alerts_id_seq'::regclass);


--
-- Name: app_audit_log id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.app_audit_log ALTER COLUMN id SET DEFAULT nextval('public.app_audit_log_id_seq'::regclass);


--
-- Name: app_settings id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.app_settings ALTER COLUMN id SET DEFAULT nextval('public.app_settings_id_seq'::regclass);


--
-- Name: auth_allowed_groups id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.auth_allowed_groups ALTER COLUMN id SET DEFAULT nextval('public.auth_allowed_groups_id_seq'::regclass);


--
-- Name: auth_allowed_users id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.auth_allowed_users ALTER COLUMN id SET DEFAULT nextval('public.auth_allowed_users_id_seq'::regclass);


--
-- Name: auth_local_users id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.auth_local_users ALTER COLUMN id SET DEFAULT nextval('public.auth_local_users_id_seq'::regclass);


--
-- Name: auth_settings id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.auth_settings ALTER COLUMN id SET DEFAULT nextval('public.auth_settings_id_seq'::regclass);


--
-- Name: license_status id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.license_status ALTER COLUMN id SET DEFAULT nextval('public.license_status_id_seq'::regclass);


--
-- Name: login_audit_log id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.login_audit_log ALTER COLUMN id SET DEFAULT nextval('public.login_audit_log_id_seq'::regclass);


--
-- Name: playbook_executions id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.playbook_executions ALTER COLUMN id SET DEFAULT nextval('public.playbook_executions_id_seq'::regclass);


--
-- Name: playbooks id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.playbooks ALTER COLUMN id SET DEFAULT nextval('public.playbooks_id_seq'::regclass);


--
-- Name: report_files id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.report_files ALTER COLUMN id SET DEFAULT nextval('public.report_files_id_seq'::regclass);


--
-- Name: scan_compare_runs id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.scan_compare_runs ALTER COLUMN id SET DEFAULT nextval('public.scan_compare_runs_id_seq'::regclass);


--
-- Name: scan_snapshots id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.scan_snapshots ALTER COLUMN id SET DEFAULT nextval('public.scan_snapshots_id_seq'::regclass);


--
-- Name: stored_credentials id; Type: DEFAULT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.stored_credentials ALTER COLUMN id SET DEFAULT nextval('public.stored_credentials_id_seq'::regclass);


--
-- Data for Name: alert_history; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.alert_history (id, alert_id, old_status, new_status, action, changed_by, created_at) FROM stdin;
1	1	1	2	Credencial/tipo de execução WinRM selecionado.	playbook	2026-05-03 22:28:20.562143
2	1	2	2	Credencial/tipo de execução WinRM selecionado.	playbook	2026-05-03 22:32:44.333689
\.


--
-- Data for Name: alerts; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.alerts (id, alert_uuid, source_system, event_number, event_type, event_type_text, display_name, username, hostname, ip_address, mitre_tactic, mitre_technique, nist_control, severity, status, raw_payload, received_at, resolved_at, resolved_by, resolution_method) FROM stdin;
1	ALERT-20260503222148-2DDA8981	ADAuditPlus	4625	Failed Logon	Failure	Multiple Failed Logon Attempts	app4	SRV-AD-01		Credential Access	T1110	AC-7	Alta	2	{"hostname": "SRV-AD-01", "severity": "Alta", "username": "app4", "event_time": "2026-05-03T19:21:47.3491080-03:00", "event_type": "Failed Logon", "ip_address": "192.168.0.50", "raw_message": "User app4 attempted multiple failed logins.", "target_user": "app4", "account_name": "app4", "display_name": "Multiple Failed Logon Attempts", "event_number": "4625", "mitre_tactic": "Credential Access", "nist_control": "AC-7", "source_system": "ADAuditPlus", "event_type_text": "Failure", "mitre_technique": "T1110"}	2026-05-03 19:21:47.349108	\N	\N	\N
\.


--
-- Data for Name: app_audit_log; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.app_audit_log (id, username, action, module, details, created_at) FROM stdin;
\.


--
-- Data for Name: app_settings; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.app_settings (id, module, setting_key, setting_value, encrypted, created_at, updated_at) FROM stdin;
1	core	theme	{"dark_mode": true, "logo_path": "logo.png"}	f	2026-05-03 22:20:13.074724	2026-05-03 22:21:32.016597
2	core	modules	{"uem": {"enabled": true, "label": "UEM"}, "security": {"enabled": true, "label": "Security"}}	f	2026-05-03 22:20:13.074724	2026-05-03 22:21:32.016597
3	core	mail_server	{"host": "", "port": 587, "username": "", "password": "", "sender": "", "from_email": "", "use_tls": true, "use_ssl": false, "whatsapp_enabled": false, "n8n_webhook_url": ""}	f	2026-05-03 22:20:13.074724	2026-05-03 22:21:32.016597
4	core	webhook	{"enabled": true, "token": "", "trusted_sources": ["192.168.0.0/24"], "require_token_external": false, "proxy_enabled": false, "trusted_proxies": [], "real_ip_header": "X-Forwarded-For"}	f	2026-05-03 22:20:13.074724	2026-05-03 22:21:32.016597
5	core	uem	{"api": {"accounts_url": "", "base_url": "", "client_id": "1000.CFDXRPJ4X8AMY2WKKTEA75ZXPMRSZI", "client_secret": "ENC:gAAAAABp98pscrWKX_OWCfW-lJSGdxH3szo97D_zWupJMgcbP3xJUFTFtmHb5qwFSvgblyrifjwNCWx1-mq59aYr1aF1vKyQLI9u0Gk313UAhy-hR5J5I6KWBkKJ56S08mv9TCRwmFV0", "refresh_token": "ENC:gAAAAABp98psiwZh63MNHXSF9tDbiHzAXVM7QaEUmaTvMY8PHxI0tlkaSH9oq9SIL-kT5Tat0Apg6byoBbrm-h_ZrYnSPI3kleUYB8n84Plq4kGPfiEPE7_0IgoGUlY8jVBHT0-MOcVR_bsM7dj2_DDxIa_3Poz11pFL7IOvlE2SttCpkOOKNh4="}, "active_directory": {"dc_host": "192.168.0.100", "ldap_port": 389, "use_ssl": false, "domain_name": "labdaniel.local", "base_dn": "", "domain_username": "labdaniel\\\\administrator", "domain_password": "ENC:gAAAAABp98psM4GnFTXwMkyM_3nvDiZbuQVRp5N8BUmGJRI0R3MYeDNKp4jW08cdX7CWXEKvAMghXq5EhmLTVVmbANO7GUmtNQ=="}, "parameters": {"cutoff_days": null, "refresh_hours": 1, "page_size": 25, "debug_mode": true}, "ip_scope": {"cidrs": []}}	f	2026-05-03 22:20:13.074724	2026-05-03 22:21:32.016597
\.


--
-- Data for Name: auth_allowed_groups; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.auth_allowed_groups (id, group_name, role, enabled, created_at) FROM stdin;
\.


--
-- Data for Name: auth_allowed_users; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.auth_allowed_users (id, username, role, enabled, created_at) FROM stdin;
\.


--
-- Data for Name: auth_local_users; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.auth_local_users (id, username, password_hash, role, enabled, must_change_password, created_at, updated_at) FROM stdin;
1	admin	pbkdf2_sha256$260000$7sHAHRo3uCN7NjGNxknmFRgjQ97tvtPV$5X2oMSiOye8Se0n+SzhXWPemLBSOr+/WDhv5K4orfTs=	admin	t	f	2026-05-03 22:18:58.269407	2026-05-03 22:19:37.646633
\.


--
-- Data for Name: auth_settings; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.auth_settings (id, ldap_server, ldap_port, use_ssl, domain_name, base_dn, enabled, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: license_status; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.license_status (id, license_id, customer_id, customer_name, domain_name, license_type, license_mode, expires_at, status, status_message, modules, max_users, max_endpoints, last_validation_at, raw_license) FROM stdin;
1	DEV-LIC-0001	centric-dev	Centric DEV	labdaniel.local	trial	offline	2027-12-31	valid	Licença válida.	{"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}	10	5000	2026-05-03 22:18:58.322536	{"modules": {"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}, "customer": "Centric DEV", "max_users": 10, "signature": "PJr60UA91dJ5+DwE5sNT3R0taCuFdtjLT7Jblu4s8Ha7ZVHHLgFCSLAJnBjsVa4QVCbHC5N5WmjHjooLwGlDlIZ/j81Of31vzPIIRkZwdwAUJOy+RWKUfkQt86Oa4pponVA/QTFVPoLK+b/bx80q5gzJxlJ7ExUT1vFj3NIuFT4kBjdT8SLU+C5R8aFMfiwL0FKByRcUxu1sjm7HuV9BWllUtjfhLs+RPcdrg670vqrED9y5B0r4ALZ5H9CH7BY4bbn4kXN1lx0wP551h9YGkNQbOXMzYaRnLKIs4umfNnYTq93YFDKO9clzEYj87udaRFuOdP3AsSwx5m7ywfTvBg==", "expires_at": "2027-12-31", "license_id": "DEV-LIC-0001", "cloud_ready": true, "customer_id": "centric-dev", "domain_name": "labdaniel.local", "license_mode": "offline", "license_type": "trial", "max_endpoints": 5000, "grace_period_days": 7, "cloud_validation_url": null}
2	DEV-LIC-0001	centric-dev	Centric DEV	labdaniel.local	trial	offline	2027-12-31	valid	Licença válida.	{"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}	10	5000	2026-05-05 16:14:42.750522	{"modules": {"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}, "customer": "Centric DEV", "max_users": 10, "signature": "PJr60UA91dJ5+DwE5sNT3R0taCuFdtjLT7Jblu4s8Ha7ZVHHLgFCSLAJnBjsVa4QVCbHC5N5WmjHjooLwGlDlIZ/j81Of31vzPIIRkZwdwAUJOy+RWKUfkQt86Oa4pponVA/QTFVPoLK+b/bx80q5gzJxlJ7ExUT1vFj3NIuFT4kBjdT8SLU+C5R8aFMfiwL0FKByRcUxu1sjm7HuV9BWllUtjfhLs+RPcdrg670vqrED9y5B0r4ALZ5H9CH7BY4bbn4kXN1lx0wP551h9YGkNQbOXMzYaRnLKIs4umfNnYTq93YFDKO9clzEYj87udaRFuOdP3AsSwx5m7ywfTvBg==", "expires_at": "2027-12-31", "license_id": "DEV-LIC-0001", "cloud_ready": true, "customer_id": "centric-dev", "domain_name": "labdaniel.local", "license_mode": "offline", "license_type": "trial", "max_endpoints": 5000, "grace_period_days": 7, "cloud_validation_url": null}
3	DEV-LIC-0001	centric-dev	Centric DEV	labdaniel.local	trial	offline	2027-12-31	valid	Licença válida.	{"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}	10	5000	2026-05-05 21:42:27.854024	{"modules": {"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}, "customer": "Centric DEV", "max_users": 10, "signature": "PJr60UA91dJ5+DwE5sNT3R0taCuFdtjLT7Jblu4s8Ha7ZVHHLgFCSLAJnBjsVa4QVCbHC5N5WmjHjooLwGlDlIZ/j81Of31vzPIIRkZwdwAUJOy+RWKUfkQt86Oa4pponVA/QTFVPoLK+b/bx80q5gzJxlJ7ExUT1vFj3NIuFT4kBjdT8SLU+C5R8aFMfiwL0FKByRcUxu1sjm7HuV9BWllUtjfhLs+RPcdrg670vqrED9y5B0r4ALZ5H9CH7BY4bbn4kXN1lx0wP551h9YGkNQbOXMzYaRnLKIs4umfNnYTq93YFDKO9clzEYj87udaRFuOdP3AsSwx5m7ywfTvBg==", "expires_at": "2027-12-31", "license_id": "DEV-LIC-0001", "cloud_ready": true, "customer_id": "centric-dev", "domain_name": "labdaniel.local", "license_mode": "offline", "license_type": "trial", "max_endpoints": 5000, "grace_period_days": 7, "cloud_validation_url": null}
4	DEV-LIC-0001	centric-dev	Centric DEV	labdaniel.local	trial	offline	2027-12-31	valid	Licença válida.	{"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}	10	5000	2026-05-06 09:12:40.664333	{"modules": {"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}, "customer": "Centric DEV", "max_users": 10, "signature": "PJr60UA91dJ5+DwE5sNT3R0taCuFdtjLT7Jblu4s8Ha7ZVHHLgFCSLAJnBjsVa4QVCbHC5N5WmjHjooLwGlDlIZ/j81Of31vzPIIRkZwdwAUJOy+RWKUfkQt86Oa4pponVA/QTFVPoLK+b/bx80q5gzJxlJ7ExUT1vFj3NIuFT4kBjdT8SLU+C5R8aFMfiwL0FKByRcUxu1sjm7HuV9BWllUtjfhLs+RPcdrg670vqrED9y5B0r4ALZ5H9CH7BY4bbn4kXN1lx0wP551h9YGkNQbOXMzYaRnLKIs4umfNnYTq93YFDKO9clzEYj87udaRFuOdP3AsSwx5m7ywfTvBg==", "expires_at": "2027-12-31", "license_id": "DEV-LIC-0001", "cloud_ready": true, "customer_id": "centric-dev", "domain_name": "labdaniel.local", "license_mode": "offline", "license_type": "trial", "max_endpoints": 5000, "grace_period_days": 7, "cloud_validation_url": null}
5	DEV-LIC-0001	centric-dev	Centric DEV	labdaniel.local	trial	offline	2027-12-31	valid	Licença válida.	{"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}	10	5000	2026-05-07 01:26:17.941468	{"modules": {"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}, "customer": "Centric DEV", "max_users": 10, "signature": "PJr60UA91dJ5+DwE5sNT3R0taCuFdtjLT7Jblu4s8Ha7ZVHHLgFCSLAJnBjsVa4QVCbHC5N5WmjHjooLwGlDlIZ/j81Of31vzPIIRkZwdwAUJOy+RWKUfkQt86Oa4pponVA/QTFVPoLK+b/bx80q5gzJxlJ7ExUT1vFj3NIuFT4kBjdT8SLU+C5R8aFMfiwL0FKByRcUxu1sjm7HuV9BWllUtjfhLs+RPcdrg670vqrED9y5B0r4ALZ5H9CH7BY4bbn4kXN1lx0wP551h9YGkNQbOXMzYaRnLKIs4umfNnYTq93YFDKO9clzEYj87udaRFuOdP3AsSwx5m7ywfTvBg==", "expires_at": "2027-12-31", "license_id": "DEV-LIC-0001", "cloud_ready": true, "customer_id": "centric-dev", "domain_name": "labdaniel.local", "license_mode": "offline", "license_type": "trial", "max_endpoints": 5000, "grace_period_days": 7, "cloud_validation_url": null}
6	DEV-LIC-0001	centric-dev	Centric DEV	labdaniel.local	trial	offline	2027-12-31	valid	Licença válida.	{"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}	10	5000	2026-05-07 01:30:03.201118	{"modules": {"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}, "customer": "Centric DEV", "max_users": 10, "signature": "PJr60UA91dJ5+DwE5sNT3R0taCuFdtjLT7Jblu4s8Ha7ZVHHLgFCSLAJnBjsVa4QVCbHC5N5WmjHjooLwGlDlIZ/j81Of31vzPIIRkZwdwAUJOy+RWKUfkQt86Oa4pponVA/QTFVPoLK+b/bx80q5gzJxlJ7ExUT1vFj3NIuFT4kBjdT8SLU+C5R8aFMfiwL0FKByRcUxu1sjm7HuV9BWllUtjfhLs+RPcdrg670vqrED9y5B0r4ALZ5H9CH7BY4bbn4kXN1lx0wP551h9YGkNQbOXMzYaRnLKIs4umfNnYTq93YFDKO9clzEYj87udaRFuOdP3AsSwx5m7ywfTvBg==", "expires_at": "2027-12-31", "license_id": "DEV-LIC-0001", "cloud_ready": true, "customer_id": "centric-dev", "domain_name": "labdaniel.local", "license_mode": "offline", "license_type": "trial", "max_endpoints": 5000, "grace_period_days": 7, "cloud_validation_url": null}
7	DEV-LIC-0001	centric-dev	Centric DEV	labdaniel.local	trial	offline	2027-12-31	valid	Licença válida.	{"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}	10	5000	2026-05-07 02:35:01.485078	{"modules": {"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}, "customer": "Centric DEV", "max_users": 10, "signature": "PJr60UA91dJ5+DwE5sNT3R0taCuFdtjLT7Jblu4s8Ha7ZVHHLgFCSLAJnBjsVa4QVCbHC5N5WmjHjooLwGlDlIZ/j81Of31vzPIIRkZwdwAUJOy+RWKUfkQt86Oa4pponVA/QTFVPoLK+b/bx80q5gzJxlJ7ExUT1vFj3NIuFT4kBjdT8SLU+C5R8aFMfiwL0FKByRcUxu1sjm7HuV9BWllUtjfhLs+RPcdrg670vqrED9y5B0r4ALZ5H9CH7BY4bbn4kXN1lx0wP551h9YGkNQbOXMzYaRnLKIs4umfNnYTq93YFDKO9clzEYj87udaRFuOdP3AsSwx5m7ywfTvBg==", "expires_at": "2027-12-31", "license_id": "DEV-LIC-0001", "cloud_ready": true, "customer_id": "centric-dev", "domain_name": "labdaniel.local", "license_mode": "offline", "license_type": "trial", "max_endpoints": 5000, "grace_period_days": 7, "cloud_validation_url": null}
8	DEV-LIC-0001	centric-dev	Centric DEV	labdaniel.local	trial	offline	2027-12-31	valid	Licença válida.	{"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}	10	5000	2026-05-07 03:29:53.512472	{"modules": {"alerts": true, "actions": true, "centric": true, "reports": true, "settings": true}, "customer": "Centric DEV", "max_users": 10, "signature": "PJr60UA91dJ5+DwE5sNT3R0taCuFdtjLT7Jblu4s8Ha7ZVHHLgFCSLAJnBjsVa4QVCbHC5N5WmjHjooLwGlDlIZ/j81Of31vzPIIRkZwdwAUJOy+RWKUfkQt86Oa4pponVA/QTFVPoLK+b/bx80q5gzJxlJ7ExUT1vFj3NIuFT4kBjdT8SLU+C5R8aFMfiwL0FKByRcUxu1sjm7HuV9BWllUtjfhLs+RPcdrg670vqrED9y5B0r4ALZ5H9CH7BY4bbn4kXN1lx0wP551h9YGkNQbOXMzYaRnLKIs4umfNnYTq93YFDKO9clzEYj87udaRFuOdP3AsSwx5m7ywfTvBg==", "expires_at": "2027-12-31", "license_id": "DEV-LIC-0001", "cloud_ready": true, "customer_id": "centric-dev", "domain_name": "labdaniel.local", "license_mode": "offline", "license_type": "trial", "max_endpoints": 5000, "grace_period_days": 7, "cloud_validation_url": null}
\.


--
-- Data for Name: login_audit_log; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.login_audit_log (id, username, source_ip, login_result, reason, created_at) FROM stdin;
1	admin	172.20.0.1	success	local role=admin	2026-05-03 22:19:26.967488
2	admin	172.20.0.1	password_changed	local bootstrap password changed	2026-05-03 22:19:37.650759
3	admin	172.20.0.1	failed	Falha na autenticação AD via LDAP: automatic bind not successful - invalidCredentials	2026-05-05 14:42:14.209159
4	admin	172.20.0.1	success	local role=admin	2026-05-05 14:42:18.379982
5	admin	192.168.0.50	success	local role=admin	2026-05-05 14:42:55.541544
6	admin	192.168.0.50	success	local role=admin	2026-05-05 14:44:19.945588
7	admin	172.20.0.1	failed	Falha na autenticação AD via LDAP: automatic bind not successful - invalidCredentials	2026-05-07 01:30:18.68729
8	admin	172.20.0.1	success	local role=admin	2026-05-07 01:30:25.20193
9	admin	172.20.0.1	failed	Falha na autenticação AD via LDAP: automatic bind not successful - invalidCredentials	2026-05-07 02:35:22.153187
10	admin	172.20.0.1	success	local role=admin	2026-05-07 02:35:26.182895
11	admin	172.20.0.1	failed	Falha na autenticação AD via LDAP: automatic bind not successful - invalidCredentials	2026-05-07 03:30:30.724494
12	admin	172.20.0.1	success	local role=admin	2026-05-07 03:30:34.96534
\.


--
-- Data for Name: playbook_executions; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.playbook_executions (id, alert_id, playbook_id, credential_id, target, variables, status, output, error, executed_by, started_at, finished_at) FROM stdin;
1	1	1	1	app4	{"ip": "192.168.0.100", "nist": "AC-7", "source": "custom", "tactic": "Credential Access", "target": "app4", "alert_id": "ALERT-20260503222148-2DDA8981", "hostname": "SRV-AD-01", "severity": "Alta", "username": "app4", "raw_alert": "{\\"db_id\\": 1, \\"id\\": 1, \\"alert_id\\": \\"ALERT-20260503222148-2DDA8981\\", \\"alert_uuid\\": \\"ALERT-20260503222148-2DDA8981\\", \\"status\\": 1, \\"status_label\\": \\"novo alarme\\", \\"received_at\\": \\"2026-05-03T19:21:47\\", \\"resolved_at\\": \\"\\", \\"resolution_type\\": \\"\\", \\"resolved_by\\": \\"\\", \\"source_system\\": \\"ADAuditPlus\\", \\"event\\": \\"Multiple Failed Logon Attempts\\", \\"event_number\\": \\"4625\\", \\"event_type\\": \\"Failed Logon\\", \\"event_type_text\\": \\"Failure\\", \\"display_name\\": \\"Multiple Failed Logon Attempts\\", \\"username\\": \\"app4\\", \\"target_user\\": \\"app4\\", \\"hostname\\": \\"SRV-AD-01\\", \\"source_ip\\": \\"192.168.0.100\\", \\"target_ip\\": \\"192.168.0.100\\", \\"ip_address\\": \\"\\", \\"technique\\": \\"T1110\\", \\"tactic\\": \\"Credential Access\\", \\"nist\\": \\"AC-7\\", \\"mitre_technique\\": \\"T1110\\", \\"mitre_tactic\\": \\"Credential Access\\", \\"nist_control\\": \\"AC-7\\", \\"severity\\": \\"Alta\\", \\"raw_payload\\": {\\"hostname\\": \\"SRV-AD-01\\", \\"severity\\": \\"Alta\\", \\"username\\": \\"app4\\", \\"event_time\\": \\"2026-05-03T19:21:47.3491080-03:00\\", \\"event_type\\": \\"Failed Logon\\", \\"ip_address\\": \\"192.168.0.50\\", \\"raw_message\\": \\"User app4 attempted multiple failed logins.\\", \\"target_user\\": \\"app4\\", \\"account_name\\": \\"app4\\", \\"display_name\\": \\"Multiple Failed Logon Attempts\\", \\"event_number\\": \\"4625\\", \\"mitre_tactic\\": \\"Credential Access\\", \\"nist_control\\": \\"AC-7\\", \\"source_system\\": \\"ADAuditPlus\\", \\"event_type_text\\": \\"Failure\\", \\"mitre_technique\\": \\"T1110\\"}, \\"execution_status\\": \\"idle\\", \\"execution_mode\\": \\"unknown\\", \\"last_execution_at\\": \\"\\", \\"last_execution_message\\": \\"\\", \\"playbook_name\\": \\"\\", \\"credential_name\\": \\"\\", \\"execution_id\\": \\"\\"}", "source_ip": "192.168.0.100", "target_ip": "192.168.0.100", "technique": "T1110", "timestamp": "", "alert_type": "", "event_type": "Failed Logon", "action_type": "alert", "resource_id": "", "target_user": "app4", "event_number": "4625", "execution_mode": "remote_winrm", "decision_reason": "Credencial/tipo de execução WinRM selecionado."}	failed		Get-ADUser : Cannot find an object with identity: '%username%' under: 'DC=labdaniel,DC=local'.\nAt line:31 char:9\n+ $user = Get-ADUser -Identity $TargetUser -ErrorAction Stop\n+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n    + CategoryInfo          : ObjectNotFound: (%username%:ADUser) [Get-ADUser], ADIdentityNotFoundException\n    + FullyQualifiedErrorId : ActiveDirectoryCmdlet:Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException,M \n   icrosoft.ActiveDirectory.Management.Commands.GetADUser	admin	2026-05-03 22:28:20.575955	2026-05-03 22:28:23.825237
2	1	2	1	app4	{"ip": "192.168.0.100", "nist": "AC-7", "source": "custom", "tactic": "Credential Access", "target": "app4", "alert_id": "ALERT-20260503222148-2DDA8981", "hostname": "SRV-AD-01", "severity": "Alta", "username": "app4", "raw_alert": "{\\"db_id\\": 1, \\"id\\": 1, \\"alert_id\\": \\"ALERT-20260503222148-2DDA8981\\", \\"alert_uuid\\": \\"ALERT-20260503222148-2DDA8981\\", \\"status\\": 2, \\"status_label\\": \\"conhecido\\", \\"received_at\\": \\"2026-05-03T19:21:47\\", \\"resolved_at\\": \\"\\", \\"resolution_type\\": \\"\\", \\"resolved_by\\": \\"\\", \\"source_system\\": \\"ADAuditPlus\\", \\"event\\": \\"Multiple Failed Logon Attempts\\", \\"event_number\\": \\"4625\\", \\"event_type\\": \\"Failed Logon\\", \\"event_type_text\\": \\"Failure\\", \\"display_name\\": \\"Multiple Failed Logon Attempts\\", \\"username\\": \\"app4\\", \\"target_user\\": \\"app4\\", \\"hostname\\": \\"SRV-AD-01\\", \\"source_ip\\": \\"192.168.0.100\\", \\"target_ip\\": \\"192.168.0.100\\", \\"ip_address\\": \\"\\", \\"technique\\": \\"T1110\\", \\"tactic\\": \\"Credential Access\\", \\"nist\\": \\"AC-7\\", \\"mitre_technique\\": \\"T1110\\", \\"mitre_tactic\\": \\"Credential Access\\", \\"nist_control\\": \\"AC-7\\", \\"severity\\": \\"Alta\\", \\"raw_payload\\": {\\"hostname\\": \\"SRV-AD-01\\", \\"severity\\": \\"Alta\\", \\"username\\": \\"app4\\", \\"event_time\\": \\"2026-05-03T19:21:47.3491080-03:00\\", \\"event_type\\": \\"Failed Logon\\", \\"ip_address\\": \\"192.168.0.50\\", \\"raw_message\\": \\"User app4 attempted multiple failed logins.\\", \\"target_user\\": \\"app4\\", \\"account_name\\": \\"app4\\", \\"display_name\\": \\"Multiple Failed Logon Attempts\\", \\"event_number\\": \\"4625\\", \\"mitre_tactic\\": \\"Credential Access\\", \\"nist_control\\": \\"AC-7\\", \\"source_system\\": \\"ADAuditPlus\\", \\"event_type_text\\": \\"Failure\\", \\"mitre_technique\\": \\"T1110\\"}, \\"execution_status\\": \\"idle\\", \\"execution_mode\\": \\"unknown\\", \\"last_execution_at\\": \\"\\", \\"last_execution_message\\": \\"\\", \\"playbook_name\\": \\"\\", \\"credential_name\\": \\"\\", \\"execution_id\\": \\"\\"}", "source_ip": "192.168.0.100", "target_ip": "192.168.0.100", "technique": "T1110", "timestamp": "", "alert_type": "", "event_type": "Failed Logon", "action_type": "alert", "resource_id": "", "target_user": "app4", "event_number": "4625", "execution_mode": "remote_winrm", "decision_reason": "Credencial/tipo de execução WinRM selecionado."}	success	Usu�rio desabilitado com sucesso: app4	#< CLIXML\r\n<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Loading Active Directory module for Windows PowerShell with default drive 'AD:'</AV><AI>0</AI><Nil /><PI>-1</PI><PC>0</PC><T>Processing</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="1"><TNRef RefId="0" /><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Loading Active Directory module for Windows PowerShell with default drive 'AD:'</AV><AI>0</AI><Nil /><PI>-1</PI><PC>25</PC><T>Processing</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="2"><TNRef RefId="0" /><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Loading Active Directory module for Windows PowerShell with default drive 'AD:'</AV><AI>0</AI><Nil /><PI>-1</PI><PC>50</PC><T>Processing</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="3"><TNRef RefId="0" /><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Loading Active Directory module for Windows PowerShell with default drive 'AD:'</AV><AI>0</AI><Nil /><PI>-1</PI><PC>75</PC><T>Processing</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="4"><TNRef RefId="0" /><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Loading Active Directory module for Windows PowerShell with default drive 'AD:'</AV><AI>0</AI><Nil /><PI>-1</PI><PC>100</PC><T>Processing</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="5"><TNRef RefId="0" /><MS><I64 N="SourceId">1</I64><PR N="Record"><AV>Loading Active Directory module for Windows PowerShell with default drive 'AD:'</AV><AI>0</AI><Nil /><PI>-1</PI><PC>100</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj><Obj S="progress" RefId="6"><TNRef RefId="0" /><MS><I64 N="SourceId">2</I64><PR N="Record"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj></Objs>	admin	2026-05-03 22:32:44.343976	2026-05-03 22:32:45.127923
\.


--
-- Data for Name: playbooks; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.playbooks (id, name, description, script_type, script_content, required_variables, metadata, enabled, created_at, updated_at) FROM stdin;
1	teste.ps1		.ps1	$ErrorActionPreference = "Stop"\n\n$TargetUser = "%username%"\n\nif ([string]::IsNullOrWhiteSpace($TargetUser)) {\n    throw "Variável username não recebida do alerta."\n}\n\nImport-Module ActiveDirectory\n\n$user = Get-ADUser -Identity $TargetUser -ErrorAction Stop\n\nDisable-ADAccount -Identity $user.SamAccountName\n\nWrite-Output "Usuário desabilitado com sucesso: $($user.SamAccountName)"\n	[]	{"name": "teste", "optional": [], "required": [], "credential": "", "description": ""}	t	2026-05-03 22:26:37.742456	2026-05-03 22:26:37.742456
2	teste2.ps1		.ps1	$ErrorActionPreference = "Stop"\n\n$TargetUser = "app4"\n\nif ([string]::IsNullOrWhiteSpace($TargetUser)) {\n    throw "Variável username não recebida do alerta."\n}\n\nImport-Module ActiveDirectory\n\n$user = Get-ADUser -Identity $TargetUser -ErrorAction Stop\n\nDisable-ADAccount -Identity $user.SamAccountName\n\nWrite-Output "Usuário desabilitado com sucesso: $($user.SamAccountName)"\n	[]	{"name": "teste2", "optional": [], "required": [], "credential": "", "description": ""}	t	2026-05-03 22:32:19.870254	2026-05-03 22:32:19.870254
\.


--
-- Data for Name: report_files; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.report_files (id, file_name, label, size_bytes, hostnames, content, created_at) FROM stdin;
1	compare_teste_2.csv	CENTRIC	474	["CSV2-TEST-01", "CSV2-TEST-02", "CSV2-TEST-03", "CSV2-TEST-04", "CSV2-TEST-05", "CSV2-TEST-06", "CSV2-TEST-07", "CSV2-TEST-08", "CSV2-TEST-09", "CSV2-TEST-10", "CSV2-TEST-11", "CSV2-TEST-12", "CSV2-TEST-13", "CSV2-TEST-14", "HYPERV-2016", "LAURAS-MACBOOK-AIR", "MACBOOK-AIR-DE-CINTIA", "NOTECENTRIC-05", "NOTECENTRIC-100", "NOTECENTRIC-11", "NOTECENTRIC-17", "NOTECENTRIC-27", "NOTECENTRIC-33", "NOTECENTRIC-37", "NOTECENTRIC-48", "NOTECENTRIC-72", "NOTECENTRIC-74", "NOTECENTRIC-79", "NOTECENTRIC-91", "NOTECENTRIC-95"]	\\xefbbbf686f73746e616d650d0a4e4f544543454e545249432d30350d0a435356322d544553542d30330d0a4e4f544543454e545249432d33370d0a4c41555241532d4d4143424f4f4b2d4149520d0a4e4f544543454e545249432d39350d0a435356322d544553542d30350d0a435356322d544553542d30310d0a435356322d544553542d30360d0a435356322d544553542d31310d0a4e4f544543454e545249432d31370d0a4e4f544543454e545249432d37340d0a4859504552562d323031360d0a435356322d544553542d31320d0a435356322d544553542d30390d0a4e4f544543454e545249432d3130300d0a435356322d544553542d31330d0a435356322d544553542d30370d0a4e4f544543454e545249432d37390d0a4e4f544543454e545249432d32370d0a435356322d544553542d30340d0a4e4f544543454e545249432d39310d0a435356322d544553542d31340d0a4e4f544543454e545249432d34380d0a4d4143424f4f4b2d4149522d44452d43494e5449410d0a4e4f544543454e545249432d33330d0a435356322d544553542d30320d0a4e4f544543454e545249432d37320d0a435356322d544553542d30380d0a4e4f544543454e545249432d31310d0a435356322d544553542d31300d0a	2026-05-05 14:45:15.382655
\.


--
-- Data for Name: scan_compare_runs; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.scan_compare_runs (id, report_name, sources, rows, total, created_at) FROM stdin;
1	Scans	{"AD": ["WIN-1HMIKG3NDP6", "WIN-5D614L5TA29"], "UEM": ["DESKTOP-8J3UMM1", "HYPERV-2016", "LAURAS-MACBOOK-AIR", "MACBOOK-AIR-DE-CINTIA", "NOTECENTRIC-05", "NOTECENTRIC-100", "NOTECENTRIC-11", "NOTECENTRIC-14", "NOTECENTRIC-17", "NOTECENTRIC-24", "NOTECENTRIC-25", "NOTECENTRIC-27", "NOTECENTRIC-32", "NOTECENTRIC-33", "NOTECENTRIC-37", "NOTECENTRIC-42", "NOTECENTRIC-48", "NOTECENTRIC-53", "NOTECENTRIC-61", "NOTECENTRIC-66", "NOTECENTRIC-70", "NOTECENTRIC-71", "NOTECENTRIC-72", "NOTECENTRIC-74", "NOTECENTRIC-75", "NOTECENTRIC-76", "NOTECENTRIC-77", "NOTECENTRIC-79", "NOTECENTRIC-84", "NOTECENTRIC-89", "NOTECENTRIC-91", "NOTECENTRIC-92", "NOTECENTRIC-94", "NOTECENTRIC-95", "NOTECENTRIC-96", "NOTECENTRIC-99", "WIN-1HMIKG3NDP6"], "CENTRIC": ["CSV2-TEST-01", "CSV2-TEST-02", "CSV2-TEST-03", "CSV2-TEST-04", "CSV2-TEST-05", "CSV2-TEST-06", "CSV2-TEST-07", "CSV2-TEST-08", "CSV2-TEST-09", "CSV2-TEST-10", "CSV2-TEST-11", "CSV2-TEST-12", "CSV2-TEST-13", "CSV2-TEST-14", "HYPERV-2016", "LAURAS-MACBOOK-AIR", "MACBOOK-AIR-DE-CINTIA", "NOTECENTRIC-05", "NOTECENTRIC-100", "NOTECENTRIC-11", "NOTECENTRIC-17", "NOTECENTRIC-27", "NOTECENTRIC-33", "NOTECENTRIC-37", "NOTECENTRIC-48", "NOTECENTRIC-72", "NOTECENTRIC-74", "NOTECENTRIC-79", "NOTECENTRIC-91", "NOTECENTRIC-95"]}	[{"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-01", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-02", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-03", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-04", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-05", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-06", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-07", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-08", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-09", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-10", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-11", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-12", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-13", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": false, "hostname": "CSV2-TEST-14", "ausente_em": "AD, UEM", "missing_in": ["AD", "UEM"], "present_in": ["CENTRIC"], "presente_em": "CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "DESKTOP-8J3UMM1", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "HYPERV-2016", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "LAURAS-MACBOOK-AIR", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "MACBOOK-AIR-DE-CINTIA", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-05", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-100", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-11", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-14", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-17", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-24", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-25", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-27", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-32", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-33", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-37", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-42", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-48", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-53", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-61", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-66", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-70", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-71", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-72", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-74", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-75", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-76", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-77", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-79", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-84", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-89", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-91", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-92", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-94", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-95", "ausente_em": "AD", "missing_in": ["AD"], "present_in": ["UEM", "CENTRIC"], "presente_em": "UEM, CENTRIC"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-96", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": false, "no_uem": true, "hostname": "NOTECENTRIC-99", "ausente_em": "AD, CENTRIC", "missing_in": ["AD", "CENTRIC"], "present_in": ["UEM"], "presente_em": "UEM"}, {"no_ad": true, "no_uem": true, "hostname": "WIN-1HMIKG3NDP6", "ausente_em": "CENTRIC", "missing_in": ["CENTRIC"], "present_in": ["AD", "UEM"], "presente_em": "AD, UEM"}, {"no_ad": true, "no_uem": false, "hostname": "WIN-5D614L5TA29", "ausente_em": "UEM, CENTRIC", "missing_in": ["UEM", "CENTRIC"], "present_in": ["AD"], "presente_em": "AD"}]	52	2026-05-05 14:45:15.391767
\.


--
-- Data for Name: scan_snapshots; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.scan_snapshots (id, source, records, record_count, source_detail, created_at) FROM stdin;
1	endpointcentral	[{"IP": "192.168.15.8", "MAC": "2c:3b:70:5a:6b:35", "full_name": "NOTECENTRIC-11", "live_status": 2, "resource_id": 31157000002452417, "agent_logged_on_users": "cintia.tobias@centric.com.br"}, {"IP": "10.202.147.115", "MAC": "78:46:5c:1a:8c:b3", "full_name": "NOTECENTRIC-95", "live_status": 2, "resource_id": 31157000002622019, "agent_logged_on_users": "--"}, {"IP": "--", "MAC": "--", "full_name": "NOTECENTRIC-37", "live_status": 2, "resource_id": 31157000003425009, "agent_logged_on_users": "--"}, {"IP": "192.168.1.3", "MAC": "60:45:2e:7d:c0:9e", "full_name": "NOTECENTRIC-05", "live_status": 2, "resource_id": 31157000004022001, "agent_logged_on_users": "--"}, {"IP": "192.168.15.4", "MAC": "8c:17:59:24:53:74", "full_name": "NOTECENTRIC-25", "live_status": 2, "resource_id": 31157000004895001, "agent_logged_on_users": "vanessa.rocha@centric.com.br"}, {"IP": "192.168.0.72", "MAC": "58:6d:67:43:25:97", "full_name": "NOTECENTRIC-14", "live_status": 2, "resource_id": 31157000005930001, "agent_logged_on_users": "--"}, {"IP": "--", "MAC": "--", "full_name": "NOTECENTRIC-27", "live_status": 2, "resource_id": 31157000006330001, "agent_logged_on_users": "misael.nunes@centric.com.br"}, {"IP": "192.168.68.59", "MAC": "60:45:2e:7e:3e:39", "full_name": "NOTECENTRIC-33", "live_status": 2, "resource_id": 31157000006650633, "agent_logged_on_users": "--"}, {"IP": "192.168.15.81", "MAC": "78:46:5c:1a:a0:6d", "full_name": "NOTECENTRIC-48", "live_status": 2, "resource_id": 31157000007082087, "agent_logged_on_users": "guilherme.silva@centric.com.br"}, {"IP": "192.168.68.116", "MAC": "9c:58:84:38:e9:28", "full_name": "MACBOOK-AIR-DE-CINTIA", "live_status": 2, "resource_id": 31157000007792633, "agent_logged_on_users": "cintiapohlmann"}, {"IP": "192.168.68.100", "MAC": "9c:58:84:3f:70:e1", "full_name": "LAURAS-MACBOOK-AIR", "live_status": 2, "resource_id": 31157000007955039, "agent_logged_on_users": "laurapohlmann"}, {"IP": "192.168.6.224", "MAC": "c8:6e:08:ba:55:63", "full_name": "NOTECENTRIC-79", "live_status": 2, "resource_id": 31157000009324055, "agent_logged_on_users": "--"}, {"IP": "192.168.31.99", "MAC": "5c:b4:7e:f9:23:ab", "full_name": "NOTECENTRIC-100", "live_status": 2, "resource_id": 31157000009855065, "agent_logged_on_users": "diogo.simiao@centric.com.br"}, {"IP": "192.168.15.15", "MAC": "5e:d3:2f:21:7b:52", "full_name": "NOTECENTRIC-17", "live_status": 2, "resource_id": 31157000009874287, "agent_logged_on_users": "thiago.matos@centric.com.br"}, {"IP": "172.20.10.4", "MAC": "3c:0a:f3:a8:54:13", "full_name": "NOTECENTRIC-72", "live_status": 2, "resource_id": 31157000009917001, "agent_logged_on_users": "leticia.assis@centric.com.br"}, {"IP": "192.168.200.153", "MAC": "28:95:29:d4:12:0f", "full_name": "NOTECENTRIC-74", "live_status": 2, "resource_id": 31157000011477003, "agent_logged_on_users": "ariane.santos@centric.com.br"}, {"IP": "192.168.0.75", "MAC": "18:31:bf:6c:e8:de", "full_name": "HYPERV-2016", "live_status": 2, "resource_id": 31157000012036685, "agent_logged_on_users": "--"}, {"IP": "10.148.79.166", "MAC": "44:a3:bb:1f:36:af", "full_name": "NOTECENTRIC-91", "live_status": 2, "resource_id": 31157000012170005, "agent_logged_on_users": "marcus.gianini@centric.com.br"}, {"IP": "192.168.15.9", "MAC": "e4:c7:67:69:a9:06", "full_name": "NOTECENTRIC-24", "live_status": 2, "resource_id": 31157000012325007, "agent_logged_on_users": "--"}, {"IP": "192.168.0.172", "MAC": "dc:56:7b:78:3a:17", "full_name": "NOTECENTRIC-77", "live_status": 2, "resource_id": 31157000012361111, "agent_logged_on_users": "leticia.alves@centric.com.br"}, {"IP": "172.24.160.1,172.20.10.3", "MAC": "00:15:5d:39:6f:16,dc:56:7b:1d:17:1d", "full_name": "NOTECENTRIC-32", "live_status": 2, "resource_id": 31157000012399527, "agent_logged_on_users": "abner.freitas@centric.com.br"}, {"IP": "54.232.189.113,192.168.15.12", "MAC": "02:00:4c:4f:4f:50,dc:56:7b:1c:85:b5", "full_name": "NOTECENTRIC-71", "live_status": 2, "resource_id": 31157000012507001, "agent_logged_on_users": "anamarta.campos@centric.com.br"}, {"IP": "172.31.224.1,192.168.15.25", "MAC": "00:15:5d:01:51:00,8c:17:59:24:52:93", "full_name": "NOTECENTRIC-84", "live_status": 2, "resource_id": 31157000012543401, "agent_logged_on_users": "leonardo.rodrigues@centric.com.br"}, {"IP": "172.28.144.1,192.168.15.5", "MAC": "00:15:5d:38:01:00,dc:56:7b:78:38:f1", "full_name": "NOTECENTRIC-70", "live_status": 2, "resource_id": 31157000012611506, "agent_logged_on_users": "gustavo.santos@centric.com.br"}, {"IP": "192.168.0.5", "MAC": "00:d7:6d:ab:30:33", "full_name": "NOTECENTRIC-42", "live_status": 2, "resource_id": 31157000012614175, "agent_logged_on_users": "diego.rios@centric.com.br"}, {"IP": "192.168.0.6", "MAC": "e4:fd:45:58:c5:4b", "full_name": "NOTECENTRIC-92", "live_status": 2, "resource_id": 31157000012677775, "agent_logged_on_users": "ana.costa@centric.com.br"}, {"IP": "192.168.100.68", "MAC": "e4:fd:45:58:c5:73", "full_name": "NOTECENTRIC-61", "live_status": 2, "resource_id": 31157000012899311, "agent_logged_on_users": "--"}, {"IP": "192.168.56.1,192.168.0.4", "MAC": "0a:00:27:00:00:24,5c:b4:7e:0d:52:1e", "full_name": "NOTECENTRIC-53", "live_status": 2, "resource_id": 31157000012928499, "agent_logged_on_users": "--"}, {"IP": "192.168.137.1,192.168.65.1,192.168.0.14", "MAC": "00:50:56:c0:00:01,00:50:56:c0:00:08,5c:b4:7e:f9:21:17", "full_name": "NOTECENTRIC-96", "live_status": 2, "resource_id": 31157000013167685, "agent_logged_on_users": "--"}, {"IP": "192.168.3.100", "MAC": "2c:3b:70:94:a0:39", "full_name": "NOTECENTRIC-89", "live_status": 2, "resource_id": 31157000013307255, "agent_logged_on_users": "diego.kenzo@centric.com.br"}, {"IP": "192.168.0.136", "MAC": "04:56:e5:48:66:83", "full_name": "NOTECENTRIC-75", "live_status": 2, "resource_id": 31157000013525453, "agent_logged_on_users": "--"}, {"IP": "192.168.1.23", "MAC": "ec:91:61:6c:cd:c1", "full_name": "NOTECENTRIC-96", "live_status": 2, "resource_id": 31157000013685607, "agent_logged_on_users": "--"}, {"IP": "--", "MAC": "--", "full_name": "DESKTOP-8J3UMM1", "live_status": 2, "resource_id": 31157000013800843, "agent_logged_on_users": "Danis"}, {"IP": "192.168.15.184", "MAC": "64:32:a8:9f:16:4f", "full_name": "NOTECENTRIC-76", "live_status": 2, "resource_id": 31157000013815768, "agent_logged_on_users": "--"}, {"IP": "--", "MAC": "--", "full_name": "NOTECENTRIC-94", "live_status": 2, "resource_id": 31157000013816310, "agent_logged_on_users": "nicholas.sanches@centric.com.br"}, {"IP": "192.168.63.151", "MAC": "5c:e0:c5:6d:06:aa", "full_name": "NOTECENTRIC-99", "live_status": 2, "resource_id": 31157000013878373, "agent_logged_on_users": "--"}, {"IP": "192.168.0.126", "MAC": "ec:91:61:6d:28:b1", "full_name": "NOTECENTRIC-66", "live_status": 2, "resource_id": 31157000013980208, "agent_logged_on_users": "--"}, {"IP": "192.168.0.99", "MAC": "00:15:5d:00:d3:16", "full_name": "WIN-1HMIKG3NDP6", "live_status": 2, "resource_id": 31157000014122580, "agent_logged_on_users": "Administrator"}]	38	api	2026-05-03 22:20:16.667647
2	ad	[{"hostname": "WIN-1HMIKG3NDP6", "dns_host_name": "WIN-1HMIKG3NDP6.labdaniel.local", "last_logon_date": "2026-03-30 15:52:56.262564+00:00"}, {"hostname": "WIN-5D614L5TA29", "dns_host_name": "WIN-5D614L5TA29.labdaniel.local", "last_logon_date": "2026-05-03 12:21:59.473566+00:00"}]	2	ldap3_ldap	2026-05-03 22:20:40.501324
\.


--
-- Data for Name: stored_credentials; Type: TABLE DATA; Schema: public; Owner: centric_user
--

COPY public.stored_credentials (id, name, credential_type, username, domain, secret_encrypted, description, metadata, enabled, created_at, updated_at) FROM stdin;
1	AD	winrm	labdaniel\\administrator		ENC:gAAAAABp98qy9wcbonmWsJEI1jazQ6oAEmC_LH3oJeLZTcgicq-H-a-8KJzng5fxOFHwawFbr_skzMeGAzJtW_L1Ke6dKSl9og==		{"host": "192.168.0.100", "port": 5985, "transport": "ntlm", "use_https": false}	t	2026-05-03 22:22:42.517612	2026-05-03 22:22:42.517612
\.


--
-- Name: alert_history_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.alert_history_id_seq', 2, true);


--
-- Name: alerts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.alerts_id_seq', 1, true);


--
-- Name: app_audit_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.app_audit_log_id_seq', 1, false);


--
-- Name: app_settings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.app_settings_id_seq', 15, true);


--
-- Name: auth_allowed_groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.auth_allowed_groups_id_seq', 1, false);


--
-- Name: auth_allowed_users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.auth_allowed_users_id_seq', 1, false);


--
-- Name: auth_local_users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.auth_local_users_id_seq', 1, true);


--
-- Name: auth_settings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.auth_settings_id_seq', 1, false);


--
-- Name: license_status_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.license_status_id_seq', 8, true);


--
-- Name: login_audit_log_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.login_audit_log_id_seq', 12, true);


--
-- Name: playbook_executions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.playbook_executions_id_seq', 2, true);


--
-- Name: playbooks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.playbooks_id_seq', 2, true);


--
-- Name: report_files_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.report_files_id_seq', 1, true);


--
-- Name: scan_compare_runs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.scan_compare_runs_id_seq', 1, true);


--
-- Name: scan_snapshots_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.scan_snapshots_id_seq', 2, true);


--
-- Name: stored_credentials_id_seq; Type: SEQUENCE SET; Schema: public; Owner: centric_user
--

SELECT pg_catalog.setval('public.stored_credentials_id_seq', 1, true);


--
-- Name: alert_history alert_history_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.alert_history
    ADD CONSTRAINT alert_history_pkey PRIMARY KEY (id);


--
-- Name: alerts alerts_alert_uuid_key; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_alert_uuid_key UNIQUE (alert_uuid);


--
-- Name: alerts alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_pkey PRIMARY KEY (id);


--
-- Name: app_audit_log app_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.app_audit_log
    ADD CONSTRAINT app_audit_log_pkey PRIMARY KEY (id);


--
-- Name: app_settings app_settings_module_setting_key_key; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.app_settings
    ADD CONSTRAINT app_settings_module_setting_key_key UNIQUE (module, setting_key);


--
-- Name: app_settings app_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.app_settings
    ADD CONSTRAINT app_settings_pkey PRIMARY KEY (id);


--
-- Name: auth_allowed_groups auth_allowed_groups_group_name_key; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.auth_allowed_groups
    ADD CONSTRAINT auth_allowed_groups_group_name_key UNIQUE (group_name);


--
-- Name: auth_allowed_groups auth_allowed_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.auth_allowed_groups
    ADD CONSTRAINT auth_allowed_groups_pkey PRIMARY KEY (id);


--
-- Name: auth_allowed_users auth_allowed_users_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.auth_allowed_users
    ADD CONSTRAINT auth_allowed_users_pkey PRIMARY KEY (id);


--
-- Name: auth_allowed_users auth_allowed_users_username_key; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.auth_allowed_users
    ADD CONSTRAINT auth_allowed_users_username_key UNIQUE (username);


--
-- Name: auth_local_users auth_local_users_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.auth_local_users
    ADD CONSTRAINT auth_local_users_pkey PRIMARY KEY (id);


--
-- Name: auth_local_users auth_local_users_username_key; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.auth_local_users
    ADD CONSTRAINT auth_local_users_username_key UNIQUE (username);


--
-- Name: auth_settings auth_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.auth_settings
    ADD CONSTRAINT auth_settings_pkey PRIMARY KEY (id);


--
-- Name: license_status license_status_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.license_status
    ADD CONSTRAINT license_status_pkey PRIMARY KEY (id);


--
-- Name: login_audit_log login_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.login_audit_log
    ADD CONSTRAINT login_audit_log_pkey PRIMARY KEY (id);


--
-- Name: playbook_executions playbook_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.playbook_executions
    ADD CONSTRAINT playbook_executions_pkey PRIMARY KEY (id);


--
-- Name: playbooks playbooks_name_key; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.playbooks
    ADD CONSTRAINT playbooks_name_key UNIQUE (name);


--
-- Name: playbooks playbooks_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.playbooks
    ADD CONSTRAINT playbooks_pkey PRIMARY KEY (id);


--
-- Name: report_files report_files_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.report_files
    ADD CONSTRAINT report_files_pkey PRIMARY KEY (id);


--
-- Name: scan_compare_runs scan_compare_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.scan_compare_runs
    ADD CONSTRAINT scan_compare_runs_pkey PRIMARY KEY (id);


--
-- Name: scan_snapshots scan_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.scan_snapshots
    ADD CONSTRAINT scan_snapshots_pkey PRIMARY KEY (id);


--
-- Name: stored_credentials stored_credentials_name_key; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.stored_credentials
    ADD CONSTRAINT stored_credentials_name_key UNIQUE (name);


--
-- Name: stored_credentials stored_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.stored_credentials
    ADD CONSTRAINT stored_credentials_pkey PRIMARY KEY (id);


--
-- Name: idx_alerts_received_at; Type: INDEX; Schema: public; Owner: centric_user
--

CREATE INDEX idx_alerts_received_at ON public.alerts USING btree (received_at DESC);


--
-- Name: idx_alerts_status; Type: INDEX; Schema: public; Owner: centric_user
--

CREATE INDEX idx_alerts_status ON public.alerts USING btree (status);


--
-- Name: idx_app_settings_module_key; Type: INDEX; Schema: public; Owner: centric_user
--

CREATE INDEX idx_app_settings_module_key ON public.app_settings USING btree (module, setting_key);


--
-- Name: idx_login_audit_created_at; Type: INDEX; Schema: public; Owner: centric_user
--

CREATE INDEX idx_login_audit_created_at ON public.login_audit_log USING btree (created_at DESC);


--
-- Name: idx_playbook_executions_started_at; Type: INDEX; Schema: public; Owner: centric_user
--

CREATE INDEX idx_playbook_executions_started_at ON public.playbook_executions USING btree (started_at DESC);


--
-- Name: idx_playbook_executions_status; Type: INDEX; Schema: public; Owner: centric_user
--

CREATE INDEX idx_playbook_executions_status ON public.playbook_executions USING btree (status);


--
-- Name: idx_report_files_created_at; Type: INDEX; Schema: public; Owner: centric_user
--

CREATE INDEX idx_report_files_created_at ON public.report_files USING btree (created_at DESC);


--
-- Name: idx_scan_compare_runs_created_at; Type: INDEX; Schema: public; Owner: centric_user
--

CREATE INDEX idx_scan_compare_runs_created_at ON public.scan_compare_runs USING btree (created_at DESC);


--
-- Name: idx_scan_snapshots_source_created; Type: INDEX; Schema: public; Owner: centric_user
--

CREATE INDEX idx_scan_snapshots_source_created ON public.scan_snapshots USING btree (source, created_at DESC);


--
-- Name: alert_history alert_history_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.alert_history
    ADD CONSTRAINT alert_history_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE CASCADE;


--
-- Name: playbook_executions playbook_executions_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.playbook_executions
    ADD CONSTRAINT playbook_executions_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE SET NULL;


--
-- Name: playbook_executions playbook_executions_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.playbook_executions
    ADD CONSTRAINT playbook_executions_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.stored_credentials(id) ON DELETE SET NULL;


--
-- Name: playbook_executions playbook_executions_playbook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: centric_user
--

ALTER TABLE ONLY public.playbook_executions
    ADD CONSTRAINT playbook_executions_playbook_id_fkey FOREIGN KEY (playbook_id) REFERENCES public.playbooks(id) ON DELETE SET NULL;


--
-- PostgreSQL database dump complete
--

\unrestrict LsZa6xDqrUBB4gCzFsxs49ZkUXbk5hcDdfbHsBO8AxaRhMis15G2TbuIBEfNeK2

