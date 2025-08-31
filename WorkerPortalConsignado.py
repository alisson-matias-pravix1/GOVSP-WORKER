import logging
from time import sleep
import requests
import re
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from lxml import html, etree
import pandas as pd
import os
from dotenv import load_dotenv


class LoginError(Exception):
    pass

class ScrappingError(Exception):
    pass

class PlaywrightError(Exception):
    pass

class CaptchaSolverError(Exception):
    pass

load_dotenv()
CHUNK_SUCCESS_SIZE = int(os.getenv("CHUNK_SUCCESS_SIZE", 250))
CHUNK_FAILURE_SIZE = int(os.getenv("CHUNK_FAILURE_SIZE", 50))
CONSECUTIVE_ERRORS_LIMIT = int(os.getenv("CONSECUTIVE_ERRORS_LIMIT", 15))
RETRIES_LIMIT = int(os.getenv("RETRIES_LIMIT", 3))

URLS = {
    "base": "https://www.portaldoconsignado.com.br/",
    "base_org": "https://www.portaldoconsignado.org.br/"
}

OUTPUT_SUCCESS_FILE_COLUMNS = [
    "cpf",
    "nome",
    "orgao",
    "identificacao",
    "mes_referencia_margem",
    "data_processamento_proxima_folha",
    "provimento",
    "lotacao",
    "cargo_funcao",
    "data_nomeacao_admissao",
    "margem_bruta_consignacoes_facultativas",
    "margem_bruta_cartao_credito",
    "margem_bruta_cartao_beneficio",
    "margem_disponivel_consignacoes_facultativas",
    "margem_disponivel_cartao_credito",
    "margem_disponivel_cartao_beneficio",
]
session = requests.Session()
LOGGER = None
OUTPUT_SUCESS_FILE_PATH = 'output_success.csv'
OUTPUT_ERRORS_FILE_PATH = 'output_errors.csv'


def set_logging(config_logger=None, level=logging.INFO):
    """
    Configura e retorna um logger global.
    - Se `config_logger` for fornecido, usa ele (ex.: logger do Airflow).
    - Caso contrário, cria um logger padrão (console).
    - Pode ajustar o nível de log com `level`.
    """
    global LOGGER

    if config_logger:
        LOGGER = config_logger
        return LOGGER

    logger = logging.getLogger("scraper")
    logger.setLevel(level)

    if not logger.handlers:  # evita duplicar handlers
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    LOGGER = logger
    return LOGGER


def clear_cpf(cpf):
    cpf_numbers = str(cpf).strip().replace(' ', '').zfill(11)
    return cpf_numbers


def transform_cpf(cpf):
    cpf_numbers = clear_cpf(cpf)
    return f"{cpf_numbers[:3]}.{cpf_numbers[3:6]}.{cpf_numbers[6:9]}-{cpf_numbers[9:]}"

def solve_captcha(payload):
    try:
        response =session.post('http://localhost:8000/predict', json=payload)
        return response.json().get('prediction', '')
    except Exception as e:
        LOGGER.error(f"Erro na comunicação com o Captcha Solver: {e}")
        raise CaptchaSolverError("Failed to request captcha solve - verify the connection between applications")

def do_login(page, login_username, login_password, tries=1):
    LOGGER.info("Acessando a tela de login...")
    try:
        if tries > RETRIES_LIMIT:
            LOGGER.error("Esgotou a quantidade de tentativas de login.")
            raise LoginError("Exceded retries limit to do login")

        page.goto(URLS["base"])
        page.click("text=Login Administrativo")
        page.click("#username")
        page.type("#username", login_username)
        page.fill("#password", login_password)
        page.locator("#cipCaptchaImg").screenshot(path=f"{login_username}.png")
        captcha_payload = {
            'image_path': fr'C:\Users\Alisson\PycharmProjects\WorkerPortalConsignado\{login_username}.png'
        }
        captcha_text = solve_captcha(captcha_payload)
        page.fill("#captcha", captcha_text)
        page.click("text=Acessar")

        sleep(2)

        if 'Grade horária fechada.' in page.content():
            LOGGER.error("Grade horária fechada.")
            raise LoginError("Access is restricted after hours. Please return during regular operating times")
        elif 'Usuário Bloqueado' in page.content():
            LOGGER.error(f"Usuário banido {login_username}")
            raise LoginError("User has been banned")

        feedback_error = page.locator("ul.feedbackPanel li.feedbackerror span")
        if feedback_error.count() > 0:
            error_message = feedback_error.first.inner_text()
            if 'caracteres digitados' in error_message.lower():
                LOGGER.warning(f"Falha no login (captcha incorreto): {error_message} - Tentativa {tries}")
                tries += 1
                return do_login(page, login_username, login_password, tries)
            elif 'dados inválidos.' in error_message.lower():
                LOGGER.error(f"Falha no login: credenciais incorretas para o usuario: {login_username}")
                raise LoginError(f"Login failed: invalid credentials: {login_username}")
            elif 'usuário sem perfil ativo cadastrado' in error_message.lower():
                LOGGER.error(f"Falha no login: {login_username} - login banido")
                raise LoginError(f"Login failed: {login_username} - login banned")
            else:
                raise LoginError(f"Login failed: {error_message}")
        return page
    except TimeoutError:
        LOGGER.error("Excedeu o tempo de espera para o carregamento da página.")
        raise LoginError("Login failed: Timeout while waiting for page to load.")


def get_tokens(page, cpf, tries=1):
    if tries > RETRIES_LIMIT:
        LOGGER.error(f"Após {tries} tentativas, não foi possível extrair os tokens para prosseguir com a extração.")
        raise PlaywrightError("Exceded retries limit to extract tokens")

    page.click("text=Consulta de Margem")

    if not 'autenticado' in page.url:
        LOGGER.error(f"Falha no login {page.url}")
        raise LoginError(f"Login failed {page.url}")

    LOGGER.info("Login realizado com sucesso!")

    page.wait_for_selector('a[href="/consignatario/pesquisarMargem"]', timeout=5000)
    page.click('a[href="/consignatario/pesquisarMargem"]')
    page.fill('#cpfServidor', transform_cpf(cpf), timeout=5000) # querying a cpf in this step avoid error to extract tokens
    page.click('input:has-text("Pesquisar")')

    cookie = page.context.cookies()[0]
    cookie_string = f"{cookie['name']}={cookie['value']}"
    current_url = page.url.replace(".com.br", ".org.br")
    ajax_baseurl = current_url.split("www.portaldoconsignado.org.br/")[1]

    page_html = page.content()
    soup = BeautifulSoup(page_html, 'html.parser')
    form = soup.find("form", attrs={"action": re.compile(r"^\./pesquisarMargem\?")})
    hidden_attribute = form.find("input", attrs={"type": "hidden"})
    btn_search_id = form.find("input", attrs={"name": "botaoPesquisar"}).get("id")
    if not btn_search_id:
        raise PlaywrightError("Search button not found in the form.")
    if not hidden_attribute:
        raise PlaywrightError("Hidden input field not found in the form.")

    try:
        path, security_token = form.attrs["action"].split("&")
        security_token =  security_token.replace("SECURITYTOKEN=", "")
        path = path.replace("./", "").split(".")[0]
        ajax_path_request = f"{URLS['base_org']}consignatario/{path}.IBehaviorListener.0-form-botaoPesquisar"
        payload = {
            "cpfServidor": "",
            "matriculaServidor": "",
            "selectOrgao": "",
            "selectProduto": "",
            "SECURITYTOKEN": security_token,
            "selectEspecie": "",
            "botaoPesquisar": 1
        }

        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
            "Cookie": cookie_string,
            "SECURITYTOKEN": security_token,
            "Wicket-Ajax": "true",
            "Wicket-Ajax-BaseURL": ajax_baseurl,
            "Wicket-FocusedElementId": btn_search_id,
            "X-Requested-With": "XMLHttpRequest, CSRF Prevention",
            "Referer": current_url
        }

        payload[hidden_attribute['name']] = ''
        return {
            "url": ajax_path_request,
            "payload": payload,
            "header": header,
        }
    except ValueError or TypeError:
        tries += 1
        get_tokens(page, tries)


def extract_all_customer_info(response_content):
    if isinstance(response_content, str):
        response_content = response_content.encode("utf-8")  # força bytes

    root = etree.fromstring(response_content)  # continua XML
    component = root.find(".//component")
    if component is None or not component.text:
        raise PlaywrightError("Can't find HTML in the XML.")
    html_content = component.text
    customer_data, customer_results = extract_costumer_from_html(html_content)
    rows = flatten_customer_results(customer_data, customer_results)
    return rows


def extract_general_info(parent_node):
    name_node = parent_node.xpath(".//div[@class='dados'][contains(text(), 'Nome - ')]/span/text()")
    cpf_node = parent_node.xpath(".//div[@class='dados'][contains(text(), 'CPF - ')]/span/text()")

    content_name = name_node[0].strip() if name_node else ""
    content_cpf = cpf_node[0].strip() if cpf_node else ""

    return {"cpf": content_cpf, "nome": content_name}


def extract_data_from_result_elements(parent_node):
    body_node = parent_node.xpath(".//div[@class='dados'][contains(text(), 'Órgão - ')]/span/text()")
    registration_node = parent_node.xpath(".//div[@class='dados'][contains(text(), 'Identificação - ')]/span/text()")
    reference_month_node = parent_node.xpath(".//div[@class='dados'][contains(text(), 'Mês de Referência da Margem - ')]/span/text()")
    processing_date_node = parent_node.xpath(".//div[@class='dados'][contains(text(), 'Data de Processamento da Próxima Folha - ')]/span/text()")

    return {
        "orgao": body_node[0].strip() if body_node else "",
        "identificacao": registration_node[0].strip() if registration_node else "",
        "mes_de_referencia_da_margem": reference_month_node[0].strip() if reference_month_node else "",
        "data_de_processamento_da_proxima_folha": processing_date_node[0].strip() if processing_date_node else ""
    }


def extract_data_from_functional_data_elements(node):
    assignment = node.xpath(".//input[@id='inputLotacao']/@value")
    employment_relationship = node.xpath(".//input[@id='inputTipoVinculo']/@value")
    appointment_date = node.xpath(".//input[@id='inputDataAdmissao']/@value")

    return {
        "lotacao": assignment[0] if assignment else "N/A",
        "cargo_funcao": employment_relationship[0] if employment_relationship else "N/A",
        "data_de_nomeacao_admissao": appointment_date[0] if appointment_date else "N/A"
    }


def extract_margin_values(parent_node, product_name):
    product_node = parent_node.xpath(f".//tr[td[span[text()='{product_name}']]]/td[2]/span/text()")
    return product_node[0].strip() if product_node else None


def extract_margins_from_html(provision_name, functional_data, gross_margin, available_margin):
    return {
        "provimento": provision_name,
        "dados_funcionais": functional_data,
        "margem_bruta": {
            "consignacoes_facultativas": extract_margin_values(gross_margin, "CONSIGNACOES FACULTATIVAS"),
            "cartao_credito": extract_margin_values(gross_margin, "CARTAO DE CREDITO"),
            "cartao_beneficio": extract_margin_values(gross_margin, "CARTÃO DE BENEFÍCIO"),
        },
        "margem_disponivel": {
            "consignacoes_facultativas": extract_margin_values(available_margin, "CONSIGNACOES FACULTATIVAS"),
            "cartao_credito": extract_margin_values(available_margin, "CARTAO DE CREDITO"),
            "cartao_beneficio": extract_margin_values(available_margin, "CARTÃO DE BENEFÍCIO"),
        }
    }


def extract_costumer_from_html(html_content):
    tree = html.fromstring(html_content)

    customer_node = tree.xpath("//div[@class='blocoDados2']")
    if not customer_node:
        return None, []
    customer = extract_general_info(customer_node[0])

    results = []
    result_nodes = tree.xpath("//div[contains(@class, 'blocoDados') and contains(@class, 'itemVisivel') and .//div[@id='painelResultado']]")

    for result_node in result_nodes:
        result = extract_data_from_result_elements(result_node)
        margins = []

        all_spans = result_node.xpath(".//div[@id='painelMargensBrutas']//div[@id='divScroll']/span")
        i = 0
        while i < len(all_spans):
            current_span = all_spans[i]
            prov_node = current_span.xpath(".//span[@class='tituloTb'][starts-with(text(), 'Provimento')]/text()")

            if prov_node:
                provision_name = prov_node[0].strip()
                functional_data = None

                if i + 1 < len(all_spans):
                    next_span = all_spans[i + 1]
                    functional_data_node = next_span.xpath(".//div[contains(@class, 'blocoDados3')]")
                    if functional_data_node:
                        functional_data = extract_data_from_functional_data_elements(functional_data_node[0])
                        i += 1  # skip to next

                gross_margin_node = current_span.xpath(".//table[@id='tabelaMargem']")
                available_margin_node = tree.xpath(f".//div[@id='painelMargensDisponiveis']//span[@class='tituloTb' and text()='{provision_name}']/parent::div/following-sibling::table[@id='tabelaMargem']")

                if gross_margin_node and available_margin_node:
                    margin = extract_margins_from_html(provision_name, [functional_data] if functional_data else [], gross_margin_node[0], available_margin_node[0])
                    margins.append(margin)

            i += 1

        result["margins"] = margins
        results.append(result)

    return customer, results

def flatten_customer_results(customer, results):
    rows = []
    for result in results:
        for margin in result.get("margins", []):
            row = {
                "cpf": customer.get("cpf"),
                "nome": customer.get("nome"),
                "orgao": result.get("orgao"),
                "identificacao": result.get("identificacao"),
                "mes_referencia_margem": result.get("mes_de_referencia_da_margem"),
                "data_processamento_proxima_folha": result.get("data_de_processamento_da_proxima_folha"),
                "provimento": margin.get("provimento"),
                "lotacao": margin["dados_funcionais"][0]["lotacao"] if margin["dados_funcionais"] else None,
                "cargo_funcao": margin["dados_funcionais"][0]["cargo_funcao"] if margin["dados_funcionais"] else None,
                "data_nomeacao_admissao": margin["dados_funcionais"][0]["data_de_nomeacao_admissao"] if margin["dados_funcionais"] else None,
                "margem_bruta_consignacoes_facultativas": margin["margem_bruta"]["consignacoes_facultativas"],
                "margem_bruta_cartao_credito": margin["margem_bruta"]["cartao_credito"],
                "margem_bruta_cartao_beneficio": margin["margem_bruta"]["cartao_beneficio"],
                "margem_disponivel_consignacoes_facultativas": margin["margem_disponivel"]["consignacoes_facultativas"],
                "margem_disponivel_cartao_credito": margin["margem_disponivel"]["cartao_credito"],
                "margem_disponivel_cartao_beneficio": margin["margem_disponivel"]["cartao_beneficio"],
            }
            rows.append(row)
    return rows


def clean_xml_declaration(content: str) -> str:
    return re.sub(r"<\?xml.*?\?>", "", content)


def process_cpfs(cpfs_to_query, session_data):
    url = session_data['url']
    payload = session_data['payload'].copy()
    success_data_to_save = []
    failures_data_to_save = []
    error_data = None
    consecutive_errors = 0

    for index, cpf in enumerate(cpfs_to_query):
        LOGGER.info(f"Processando CPF {index+1}/{len(cpfs_to_query)}: {cpf}")
        if len(success_data_to_save) >= CHUNK_SUCCESS_SIZE:
            save_success(success_data_to_save)
            success_data_to_save.clear()
        if len(failures_data_to_save) >= CHUNK_FAILURE_SIZE:
            save_error(failures_data_to_save)
            failures_data_to_save.clear()
        if consecutive_errors >= CONSECUTIVE_ERRORS_LIMIT:
            LOGGER.error(f"Esgotou o limite de erros consecutivos ({CONSECUTIVE_ERRORS_LIMIT}). Interrompendo o processamento.")
            break

        payload['cpfServidor'] = transform_cpf(cpf)
        post_query_cpf = session.post(url, data=payload, headers=session_data['header'])
        post_query_cpf.raise_for_status()

        if 'Valor da margem indisponível.' in post_query_cpf.text:
            LOGGER.warning(f"CPF {cpf}: Valor da margem indisponível.")
            failures_data_to_save.append({'cpf': cpf, 'causa': 'Valor da margem indisponível.'})
            continue
        elif 'Servidor não permite a Consulta da Margem' in post_query_cpf.text:
            LOGGER.warning(f"CPF {cpf}: Servidor não permite a consulta.")
            failures_data_to_save.append({'cpf': cpf, 'causa': 'Servidor não permite a Consulta da Margem'})
            continue
        elif 'Dados de cadastro não localizados.' in post_query_cpf.text:
            LOGGER.warning(f"CPF {cpf}: Dados de cadastro não localizados.")
            failures_data_to_save.append({'cpf': cpf, 'causa': 'Dados de cadastro não localizados.'})
            continue

        results = extract_all_customer_info(post_query_cpf.text)

        if not results:
            consecutive_errors += 1
            if error_data is None:
                error_data = {'begin_index': index, 'end_index': len(cpfs_to_query)-1}
            continue

        for result in results:
            success_data_to_save.append(result)
        error_data = None
    flush_records(success_data_to_save, failures_data_to_save)
    if consecutive_errors < CONSECUTIVE_ERRORS_LIMIT:
        LOGGER.info("Processamento concluído com sucesso.")
        error_data = None
    return error_data


def flush_records(success_records, error_records):
    if len(success_records) > 0:
        LOGGER.info(f"Salvando sucessos restantes: {len(success_records)}")
        save_success(success_records)
    if len(error_records) > 0:
        LOGGER.info(f"Salvando erros restantes: {len(error_records)}")
        save_error(error_records)


def save_success(records):
    df = pd.DataFrame(records)
    df.to_csv(OUTPUT_SUCESS_FILE_PATH, mode='a', header=not pd.io.common.file_exists(OUTPUT_SUCESS_FILE_PATH), index=False, sep=';')


def save_error(records):
    df = pd.DataFrame(records)
    df.to_csv(OUTPUT_ERRORS_FILE_PATH, mode='a', header=not pd.io.common.file_exists(OUTPUT_ERRORS_FILE_PATH), index=False, sep=';')

def set_output_paths(success_path: str, error_path: str):
    global OUTPUT_SUCESS_FILE_PATH, OUTPUT_ERRORS_FILE_PATH
    if success_path is not None:
        OUTPUT_SUCESS_FILE_PATH = success_path
    if error_path is not None:
        OUTPUT_ERRORS_FILE_PATH = error_path

def parse_bool(value):
    return value == "1" or value == 1
def start(user, password, cpfs_to_query, output_success_file_path=None, output_error_file_path=None, config_logger=None, log_level=logging.INFO):
    set_output_paths(output_success_file_path, output_error_file_path)
    set_logging(config_logger, log_level)

    debug = parse_bool(os.getenv('DEBUG', False))

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not debug)
        page = browser.new_page()
        do_login(page, user, password)
        session_data = get_tokens(page, cpfs_to_query[0])
        browser.close()

    residuals = process_cpfs(cpfs_to_query, session_data)
    if residuals is not None:
        residuals['login'] = user
    return residuals


