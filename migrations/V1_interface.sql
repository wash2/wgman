-- Table: public.Interface

-- DROP TABLE public."Interface";

CREATE TABLE public."Interface"
(
    id uuid NOT NULL DEFAULT uuid_generate_v4(),
    name text COLLATE pg_catalog."default" NOT NULL,
    public_key character(45)[] COLLATE pg_catalog."default",
    port integer,
    ip inet,
    fqdn character varying(253)[] COLLATE pg_catalog."default",
    CONSTRAINT "Account_pkey" PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE public."Interface"
    OWNER to postgres;
