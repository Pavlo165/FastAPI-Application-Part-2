from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from elasticsearch import Elasticsearch
import os
import json
from datetime import datetime, timedelta

app = FastAPI()
JSON_FILE = "known_exploited_vulnerabilities.json"

# attache static file
app.mount("/static", StaticFiles(directory="static"), name="static")

# html template
templates = Jinja2Templates(directory="template")

client = Elasticsearch(
    "https://b90aee695fef4cc2977f226296ebc5e1.us-central1.gcp.cloud.es.io:443",
    api_key=os.getenv("ELASTICSEARCH_API_KEY")
)


@app.get("/init-db")
def init_db():
    """
    Initialize the database
    """
    if not os.path.exists(JSON_FILE):
        raise FileNotFoundError(f"Where file?")

    try:
        if client.indices.exists(index="vulnerabilities"):
            return {"message": "Index 'vulnerabilities' already exists."}

        with open(JSON_FILE, "r") as file:
            data = json.load(file)

        vulnerabilities = data["vulnerabilities"]

        for vulnerability in vulnerabilities:
            cve_id = vulnerability["cveID"]
            client.index(index="vulnerabilities", id=cve_id, document=vulnerability)

        return {"message": "Database initialized successfully.", "count": len(vulnerabilities)}

    except Exception as e:
        print(f"Error: {e}")



@app.get("/info", response_class=HTMLResponse)
def get_info(request: Request):
    """
    Return info about autor
    """
    context = {
        "request": request,
        "app_name": "FastAPI Application",
        "description": "This application allows you to get information about CVEs. Data is stored on Elasticsearch.",
        "author": "Mochurad Pavlo",
        "email": "mothuradpavlo@gmail.com",
    }

    return templates.TemplateResponse("info.html", context)


@app.get("/get/all/{page}", response_class=HTMLResponse)
def get_all(request: Request, page: int):
    """
    Return all CVEs from Elasticsearch (last 30 days).
    """
    try:
        if not client.indices.exists(index="vulnerabilities"):
            raise HTTPException(status_code=404, detail="Index 'vulnerabilities' does not exist.")

        current_date = datetime.utcnow()
        date_threshold = (current_date - timedelta(days=30)).strftime("%Y-%m-%d")

        # Elasticsearch query
        query = {
            "query": {
                "range": {
                    "dateAdded": {
                        "gte": date_threshold,
                        "format": "yyyy-MM-dd"
                    }
                }
            },
            "sort": [
                {"dateAdded": {"order": "desc"}}
            ],
            "from": (page - 1) * 40,
            "size": 40
        }

        response = client.search(index="vulnerabilities", body=query)
        # print(response)
        vulnerabilities = [
            hit["_source"] for hit in response["hits"]["hits"]
        ]

        
        total_hits = response["hits"]["total"]["value"]
        total_pages = (total_hits + 40 - 1) // 40

        if not vulnerabilities or page < 1 or page > total_pages:
            raise HTTPException(status_code=404, detail="Page not found.")

        return templates.TemplateResponse(
            "getall.html",
            {
                "request": request,
                "cves": vulnerabilities,
                "page": page,
                "total_pages": total_pages,
            },
        )

    except Exception as e:
        print(f"Error: {e}")


@app.get("/get/new", response_class=HTMLResponse)
def get_new(request: Request):
    """
    Return only the 10 newest CVEs from Elasticsearch.
    """
    try:
        if not client.indices.exists(index="vulnerabilities"):
            raise HTTPException(status_code=404, detail="Index 'vulnerabilities' does not exist.")

        # Elasticsearch
        query = {
            "query": {
                "match_all": {}
            },
            "sort": [
                {"dateAdded": {"order": "desc"}}
            ],
            "size": 10
        }

        response = client.search(index="vulnerabilities", body=query)
        # print(response["hits"]["hits"])
        latest_vulnerabilities = [
            hit["_source"] for hit in response["hits"]["hits"]
        ]

        return templates.TemplateResponse(
            "getnew.html",
            {
                "request": request,
                "cves": latest_vulnerabilities,
            },
        )
    
    except Exception as e:
        print(f"Error: {e}")



@app.get("/get/known", response_class=HTMLResponse)
def get_known(request: Request):
    """
    Return only CVEs with knownRansomwareCampaignUse
    """
    try:
        if not client.indices.exists(index="vulnerabilities"):
            raise HTTPException(status_code=404, detail="Index 'vulnerabilities' does not exist.")

        # Elasticsearch auery
        query = {
            "query": {
                "term": {
                    "knownRansomwareCampaignUse.keyword": "Known"
                }
            },
            "sort": [
                {"dateAdded": {"order": "desc"}}
            ],
            "size": 10
        }

        response = client.search(index="vulnerabilities", body=query)

        known_vulnerabilities = [
            hit["_source"] for hit in response["hits"]["hits"]
        ]

        return templates.TemplateResponse(
            "getknow.html",
            {
                "request": request,
                "cves": known_vulnerabilities,
            },
        )
    
    except Exception as e:
        print(f"Error: {e}")



@app.get("/get", response_class=HTMLResponse)
def search_cve(request: Request, query: str = Query(..., min_length=1)):
    """
    Search for CVEs containing the query word in Elasticsearch.
    """
    try:
        if not client.indices.exists(index="vulnerabilities"):
            raise HTTPException(status_code=404, detail="Index 'vulnerabilities' does not exist.")

        # Elasticsearch query
        search_query = {
            "query": {
                "multi_match": {
                    "query": query,
                    "fields": ["vendorProject","product", "vulnerabilityName", "shortDescription","requiredAction", "notes"],  # Поля для пошуку
                    "fuzziness": "AUTO"
                }
            },
            "size": 40
        }

        response = client.search(index="vulnerabilities", body=search_query)

        filtered_vulnerabilities = [
            hit["_source"] for hit in response["hits"]["hits"]
        ]

        if not filtered_vulnerabilities:
            raise HTTPException(status_code=404, detail=f"CVE not found for query '{query}'.")

        return templates.TemplateResponse(
            "getsearch.html",
            {
                "request": request,
                "query": query,
                "cves": filtered_vulnerabilities,
            },
        )
    
    except Exception as e:
        print(f"Error: {e}")