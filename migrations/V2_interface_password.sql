-- Table: public.InterfacePassword

-- DROP TABLE public."InterfacePassword";

CREATE TABLE public."InterfacePassword"
(
    id uuid NOT NULL,
    password_hash character varying(128) COLLATE pg_catalog."default" NOT NULL,
    salt character varying(128) COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT "InterfacePassword_pkey" PRIMARY KEY (id),
    CONSTRAINT id FOREIGN KEY (id)
        REFERENCES public."Interface" (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
)

TABLESPACE pg_default;

ALTER TABLE public."InterfacePassword"
    OWNER to postgres;
