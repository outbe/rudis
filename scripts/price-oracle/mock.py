#!/usr/bin/env python3
"""
Gold-based Price Server for Price-Feeder

This HTTP server fetches real XAU/USD (gold) prices from fxpricing.com
and calculates COEN/USDC based on gold price changes.

Initial COEN/USDC = 0.01, backed by a fixed amount of gold grams.
When gold price changes, COEN/USDC changes proportionally.

Usage:
    python mock_price_server.py --port 8080 --interval 30

Endpoints:
    GET /api/pairs              - List all available trading pairs (XAUUSD, COENUSDC)
    GET /api/tickers?symbols=   - Get current prices for specified symbols
    GET /api/candles?symbols=   - Get candle data for specified symbols
    GET /health                 - Health check endpoint
"""

import argparse
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install with: pip install requests")
    sys.exit(1)

# Gold and COEN configuration
TROY_OUNCE_TO_GRAMS = 31.1035
INITIAL_COEN_PRICE_USDC = 0.01
GOLD_PRICE_URL = "https://fxpricing.com/xau-usd/gold-spot-us-dollar"
DEFAULT_GOLD_PRICE = 5553.94  # Fallback price if scraping fails (USD per troy oz)
REQUEST_TIMEOUT = 10  # seconds
AMPLIFICATION_FACTOR = 10  # 10x amplification: gold +1% -> COEN +10%

# Default pairs configuration
DEFAULT_PAIRS = {
    "XAUUSD": {"price": DEFAULT_GOLD_PRICE, "volume": 500.0},
    "COEN840": {"price": INITIAL_COEN_PRICE_USDC, "volume": 1000000.0},
}

DEFAULT_UPDATE_INTERVAL = 5  # seconds


class PriceStore:
    """Thread-safe storage for price data with automatic updates from real gold prices."""

    def __init__(
        self,
        update_interval: float = DEFAULT_UPDATE_INTERVAL,
    ):
        self.prices: Dict[str, Dict[str, float]] = {}
        self.update_interval = update_interval
        self.lock = threading.Lock()
        self._running = False
        self._update_thread = None

        # Gold price tracking
        self.last_gold_price: float = DEFAULT_GOLD_PRICE
        self.initial_gold_price: float = DEFAULT_GOLD_PRICE
        self.gold_grams_per_coen: float = 0.0

        # Fetch initial gold price and calculate COEN parameters
        self._initialize_prices()

    def _fetch_gold_price(self) -> Optional[float]:
        """Fetch real gold price from fxpricing.com by scraping HTML."""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            }
            response = requests.get(
                GOLD_PRICE_URL, headers=headers, timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()

            # Extract gold price from HTML: <b class='XAU-USD-price'>XXXX</b>
            match = re.search(
                r"<b class=['\"]XAU-USD-price['\"]>\s*([\d,]+\.?\d*)\s*</b>",
                response.text,
            )
            if match:
                price_str = match.group(1).replace(",", "")
                gold_price = float(price_str)
                print(f"Fetched gold price: ${gold_price:.2f}/oz")
                return gold_price
            else:
                print("Warning: Could not find gold price in HTML, using fallback")
                return None
        except requests.RequestException as e:
            print(f"Warning: Failed to fetch gold price: {e}")
            return None
        except (ValueError, AttributeError) as e:
            print(f"Warning: Failed to parse gold price: {e}")
            return None

    def _calculate_coen_price(self, gold_price: float) -> float:
        """Calculate COEN/USDC price based on current gold price with 10x amplification."""
        # Calculate gold price change ratio
        gold_change_ratio = gold_price / self.initial_gold_price
        # Apply 10x amplification to the change
        amplified_multiplier = 1 + AMPLIFICATION_FACTOR * (gold_change_ratio - 1)
        # Return amplified COEN price (prevent negative)
        return max(INITIAL_COEN_PRICE_USDC * amplified_multiplier, 0)

    def _initialize_prices(self):
        """Initialize prices with real gold data."""
        # Fetch initial gold price
        fetched_price = self._fetch_gold_price()
        if fetched_price is not None:
            self.initial_gold_price = fetched_price
            self.last_gold_price = fetched_price
        else:
            print(f"Using default gold price: ${DEFAULT_GOLD_PRICE:.2f}/oz")
            self.initial_gold_price = DEFAULT_GOLD_PRICE
            self.last_gold_price = DEFAULT_GOLD_PRICE

        # Calculate gold grams per COEN at initial price
        # Initial COEN price = 0.01 USDC
        # gold_grams_per_coen = initial_coen_price / gold_price_per_gram
        initial_gold_per_gram = self.initial_gold_price / TROY_OUNCE_TO_GRAMS
        self.gold_grams_per_coen = INITIAL_COEN_PRICE_USDC / initial_gold_per_gram

        print(
            f"Initial gold price: ${self.initial_gold_price:.2f}/oz (${initial_gold_per_gram:.4f}/gram)"
        )
        print(f"Gold grams per COEN: {self.gold_grams_per_coen:.10f}")
        print(f"Initial COEN/USDC: {INITIAL_COEN_PRICE_USDC}")

        # Initialize price store
        current_time = int(time.time()) * 1000
        self.prices = {
            "XAUUSD": {
                "price": self.last_gold_price,
                "volume": 500.0,
                "timestamp": current_time,
            },
            "COEN840": {
                "price": INITIAL_COEN_PRICE_USDC,
                "volume": 1000000.0,
                "timestamp": current_time,
            },
            "USDCUSD": {"price": 1.0, "volume": 100000.0, "timestamp": current_time},
            "USDTUSD": {"price": 1.0, "volume": 100000.0, "timestamp": current_time},
            "BTCUSDC": {"price": 104000.0, "volume": 50000.0, "timestamp": current_time},
            "ETHUSDC": {"price": 3300.0, "volume": 100000.0, "timestamp": current_time},
        }

    def start_updates(self):
        """Start background price updates."""
        self._running = True
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()
        print(f"Price updates started (interval: {self.update_interval}s)")

    def stop_updates(self):
        """Stop background price updates."""
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=2)

    def _update_loop(self):
        """Background loop to update prices."""
        while self._running:
            time.sleep(self.update_interval)
            self._update_prices()

    def _update_prices(self):
        """Update prices by fetching real gold price and calculating COEN."""
        # Fetch current gold price
        fetched_price = self._fetch_gold_price()
        if fetched_price is not None:
            self.last_gold_price = fetched_price

        # Calculate new COEN price based on current gold price
        new_coen_price = self._calculate_coen_price(self.last_gold_price)

        current_time = int(time.time()) * 1000

        with self.lock:
            # Update XAU/USD
            self.prices["XAUUSD"]["price"] = round(self.last_gold_price, 2)
            self.prices["XAUUSD"]["timestamp"] = current_time

            # Update COEN/USDC and COEN/0XUSD (same price)
            self.prices["COEN840"]["price"] = round(new_coen_price, 10)
            self.prices["COEN840"]["timestamp"] = current_time

            # Update other asset timestamps to prevent staleness
            for symbol in ["USDCUSD", "USDTUSD", "BTCUSDC", "ETHUSDC"]:
                if symbol in self.prices:
                    self.prices[symbol]["timestamp"] = current_time

            print(f"Prices updated: {self._format_prices()}")

    def _format_prices(self) -> str:
        """Format prices for logging."""
        parts = []
        for symbol, data in self.prices.items():
            price = data["price"]
            if price < 1:
                parts.append(f"{symbol}={price:.8f}")  # More decimals for small prices
            else:
                parts.append(f"{symbol}={price:.2f}")
        return ", ".join(parts)

    def get_prices(self, symbols: list) -> list:
        """Get prices for specified symbols."""
        with self.lock:
            result = []
            for symbol in symbols:
                symbol_upper = symbol.upper()
                if symbol_upper in self.prices:
                    data = self.prices[symbol_upper]
                    result.append(
                        {
                            "symbol": symbol_upper,
                            "price": f"{data['price']:.18f}",
                            "volume": f"{data['volume']:.8f}",
                        }
                    )
            return result

    def get_candles(self, symbols: list) -> list:
        """Get candle data for specified symbols."""
        with self.lock:
            result = []
            for symbol in symbols:
                symbol_upper = symbol.upper()
                if symbol_upper in self.prices:
                    data = self.prices[symbol_upper]
                    result.append(
                        {
                            "symbol": symbol_upper,
                            "price": f"{data['price']:.18f}",
                            "volume": f"{data['volume']:.8f}",
                            "timestamp": data["timestamp"],
                        }
                    )
            return result

    def get_all_pairs(self) -> list:
        """Get list of all available pairs."""
        with self.lock:
            return list(self.prices.keys())


class MockPriceHandler(BaseHTTPRequestHandler):
    """HTTP request handler for mock price server."""

    price_store: Optional[PriceStore] = None

    def log_message(self, format, *args):
        """Custom log format."""
        print(f"[{self.log_date_time_string()}] {format % args}")

    def send_json_response(self, data: Any, status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/pairs":
            self.handle_pairs()
        elif path == "/api/tickers":
            self.handle_tickers(query)
        elif path == "/api/candles":
            self.handle_candles(query)
        elif path == "/health":
            self.send_json_response({"status": "ok"})
        else:
            self.send_json_response({"error": "Not found"}, 404)

    def handle_pairs(self):
        """Handle /api/pairs endpoint."""
        pairs = self.price_store.get_all_pairs()
        self.send_json_response({"pairs": pairs})

    def handle_tickers(self, query: dict):
        """Handle /api/tickers endpoint."""
        symbols_param = query.get("symbols", [""])[0]
        if not symbols_param:
            # Return all tickers if no symbols specified
            symbols = self.price_store.get_all_pairs()
        else:
            symbols = [s.strip() for s in symbols_param.split(",") if s.strip()]

        data = self.price_store.get_prices(symbols)
        self.send_json_response({"data": data})

    def handle_candles(self, query: dict):
        """Handle /api/candles endpoint."""
        symbols_param = query.get("symbols", [""])[0]
        if not symbols_param:
            symbols = self.price_store.get_all_pairs()
        else:
            symbols = [s.strip() for s in symbols_param.split(",") if s.strip()]

        data = self.price_store.get_candles(symbols)
        self.send_json_response({"data": data})


def main():
    parser = argparse.ArgumentParser(
        description="Gold-based Price Server for Price-Feeder (XAU/USD and COEN/USDC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Start with default configuration
    python mock_price_server.py

    # Start with custom port
    python mock_price_server.py --port 8080

    # Start with custom update interval
    python mock_price_server.py --interval 30

This server fetches real XAU/USD gold prices and calculates COEN/USDC
based on gold price changes. Initial COEN/USDC = 0.01, backed by gold.
        """,
    )
    parser.add_argument(
        "--host", type=str, default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=8080, help="Port to listen on (default: 8080)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_UPDATE_INTERVAL,
        help=f"Price update interval in seconds (default: {DEFAULT_UPDATE_INTERVAL})",
    )

    args = parser.parse_args()

    # Initialize price store (fetches initial gold price)
    print("Initializing price store...")
    price_store = PriceStore(update_interval=args.interval)

    # Set up handler with price store
    MockPriceHandler.price_store = price_store

    # Start price updates
    price_store.start_updates()

    # Create and start HTTP server
    server = HTTPServer((args.host, args.port), MockPriceHandler)
    print(f"\nGold Price Server starting on http://{args.host}:{args.port}")
    print(f"Available pairs: {', '.join(price_store.get_all_pairs())}")
    print(f"Update interval: {args.interval}s")
    print(f"Gold source: {GOLD_PRICE_URL}")
    print("\nEndpoints:")
    print(f"  GET http://{args.host}:{args.port}/api/pairs")
    print(f"  GET http://{args.host}:{args.port}/api/tickers?symbols=XAUUSD,COENUSDC")
    print(f"  GET http://{args.host}:{args.port}/api/candles?symbols=XAUUSD")
    print(f"  GET http://{args.host}:{args.port}/health")
    print("\nPress Ctrl+C to stop...")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        price_store.stop_updates()
        server.shutdown()


if __name__ == "__main__":
    main()
