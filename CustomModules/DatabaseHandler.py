"""
Database Handler Module

Provides centralized async database connection management supporting multiple database systems:
- SQLite (with WAL mode and optimizations)
- MySQL
- MariaDB
- PostgreSQL
- MongoDB

Usage:
    from CustomModules.DatabaseHandler import DatabaseHandler

    # Initialize with connection string
    db_handler = await DatabaseHandler.create(
        connection_string="sqlite://GitHub_Events_Limiter/data.db",
        logger=logger
    )

    # Execute query (auto-detects SQL vs NoSQL)
    result = await db_handler.execute(
        "SELECT * FROM api_keys WHERE id = ?",
        (key_id,),
        fetch="one"
    )

    # Insert with commit
    await db_handler.execute(
        "INSERT INTO ...",
        params,
        commit=True
    )

    # Close connections
    await db_handler.close()

Connection String Format:
    - SQLite: sqlite://path/to/db.db
    - MySQL: mysql://user:password@host:port/database
    - MariaDB: mariadb://user:password@host:port/database
    - PostgreSQL: postgresql://user:password@host:port/database
    - MongoDB: mongodb://user:password@host:port/database

Backwards Compatibility:
    For legacy sync code, use DatabaseHandler with a file path:
    db_handler = DatabaseHandler("GitHub_Events_Limiter/data.db", logger)
"""

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple, Union, Type
from urllib.parse import urlparse


class BaseDatabaseBackend(ABC):
    """Abstract base class for database backends"""

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.logger: logging.Logger = logger or logging.getLogger(__name__)

    @abstractmethod
    async def connect(self, connection_params: Dict[str, Any]) -> None:
        """Establish database connection"""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close database connection"""
        pass

    @abstractmethod
    async def execute(
        self,
        query: str,
        params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None,
        commit: bool = False,
        fetch: Optional[Union[str, bool]] = None,  # Can be 'one', 'all', False (for rowcount), or None
    ) -> Optional[Union[List[Dict[str, Any]], Dict[str, Any], int]]:
        """Execute a database query"""
        pass

    @abstractmethod
    async def execute_many(
        self, query: str, params_list: List[Union[Tuple[Any, ...], Dict[str, Any]]], commit: bool = True
    ) -> int:
        """Execute a query multiple times with different parameters"""
        pass

    @abstractmethod
    def convert_query(self, query: str, params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None) -> Tuple[str, Any]:
        """Convert query to backend-specific format"""
        pass


class SQLiteBackend(BaseDatabaseBackend):
    """SQLite database backend with WAL mode and optimizations"""
    
    DB_NOT_CONNECTED_ERROR = "Database connection not established"

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        super().__init__(logger)
        self.connection: Optional[Any] = None  # aiosqlite.Connection
        self.db_path: Optional[str] = None

    async def connect(self, connection_params: Dict[str, Any]) -> None:
        """Establish SQLite connection with optimizations"""
        import aiosqlite

        self.db_path = connection_params.get("path")
        if self.db_path is None:
            raise ValueError("SQLite database path is required")
            
        self.connection = await aiosqlite.connect(self.db_path)
        self.connection.row_factory = aiosqlite.Row

        # Enable WAL mode for better concurrent performance
        await self.connection.execute("PRAGMA journal_mode=WAL")
        await self.connection.execute("PRAGMA synchronous=NORMAL")
        await self.connection.execute("PRAGMA cache_size=-64000")
        await self.connection.execute("PRAGMA temp_store=MEMORY")
        await self.connection.execute("PRAGMA mmap_size=268435456")
        await self.connection.execute("PRAGMA busy_timeout=5000")

        self.logger.debug(f"SQLite connection established: {self.db_path}")

    async def close(self) -> None:
        """Close SQLite connection"""
        if self.connection:
            await self.connection.close()
            self.logger.debug("SQLite connection closed")

    def convert_query(self, query: str, params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None) -> Tuple[str, Any]:
        """SQLite uses ? placeholders - no conversion needed"""
        return query, params

    async def execute(
        self,
        query: str,
        params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None,
        commit: bool = False,
        fetch: Optional[Union[str, bool]] = None,
    ) -> Optional[Union[List[Dict[str, Any]], Dict[str, Any], int]]:
        """Execute SQLite query"""
        query, params = self.convert_query(query, params)

        if self.connection is None:
            raise RuntimeError(self.DB_NOT_CONNECTED_ERROR)
            
        async with self.connection.cursor() as cursor:
            try:
                if params:
                    await cursor.execute(query, params)
                else:
                    await cursor.execute(query)

                result: Optional[Union[List[Dict[str, Any]], Dict[str, Any], int]] = None
                if fetch == "one":
                    row = await cursor.fetchone()
                    result = dict(row) if row else None
                elif fetch == "all":
                    rows = await cursor.fetchall()
                    result = [dict(row) for row in rows]
                elif fetch is False:
                    result = cursor.rowcount

                if commit:
                    await self.connection.commit()
                    self.logger.debug("Committed transaction")

                return result

            except Exception as e:
                await self.connection.rollback()
                self.logger.error(f"SQLite query execution error: {e}")
                raise

    async def execute_many(
        self, query: str, params_list: List[Union[Tuple[Any, ...], Dict[str, Any]]], commit: bool = True
    ) -> int:
        """Execute SQLite query multiple times"""
        query, _ = self.convert_query(query)

        if self.connection is None:
            raise RuntimeError(self.DB_NOT_CONNECTED_ERROR)
            
        async with self.connection.cursor() as cursor:
            try:
                await cursor.executemany(query, params_list)
                rowcount = cursor.rowcount

                if commit:
                    await self.connection.commit()
                    self.logger.debug(f"Committed batch transaction: {rowcount} rows affected")

                return rowcount

            except Exception as e:
                await self.connection.rollback()
                self.logger.error(f"SQLite batch query execution error: {e}")
                raise

    async def checkpoint_wal(self) -> None:
        """Run a WAL checkpoint to flush all changes to the main .db file"""
        if self.connection is None:
            raise RuntimeError(self.DB_NOT_CONNECTED_ERROR)
            
        try:
            await self.connection.execute("PRAGMA wal_checkpoint(FULL);")
            self.logger.info("WAL checkpoint completed")
        except Exception as e:
            self.logger.error(f"Error running WAL checkpoint: {e}")
            raise


class MySQLBackend(BaseDatabaseBackend):
    """MySQL/MariaDB database backend"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        self.pool: Any = None  # aiomysql.Pool type not available
        self.connection_params: Optional[Dict[str, Any]] = None

    async def connect(self, connection_params: Dict[str, Any]) -> None:
        """Establish MySQL connection pool"""
        import aiomysql

        self.connection_params = connection_params
        self.pool = await aiomysql.create_pool(
            host=connection_params.get("host", "localhost"),
            port=connection_params.get("port", 3306),
            user=connection_params.get("user"),
            password=connection_params.get("password"),
            db=connection_params.get("database"),
            autocommit=False,
            minsize=1,
            maxsize=10,
        )
        self.logger.debug(f"MySQL connection pool established: {connection_params.get('database')}")

    async def close(self) -> None:
        """Close MySQL connection pool"""
        if self.pool:
            self.pool.close()
            await self.pool.wait_closed()
            self.logger.debug("MySQL connection pool closed")

    def convert_query(self, query: str, params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None) -> Tuple[str, Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]]]:
        """Convert SQLite ? placeholders to MySQL %s placeholders"""
        converted_query = query.replace("?", "%s")
        
        # Convert SQLite AUTOINCREMENT to MySQL AUTO_INCREMENT
        converted_query = converted_query.replace("AUTOINCREMENT", "AUTO_INCREMENT")
        
        # Convert CURRENT_TIMESTAMP default syntax if needed
        converted_query = re.sub(
            r"DEFAULT\s+CURRENT_TIMESTAMP",
            "DEFAULT CURRENT_TIMESTAMP",
            converted_query,
            flags=re.IGNORECASE
        )
        
        return converted_query, params

    async def execute(
        self,
        query: str,
        params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None,
        commit: bool = False,
        fetch: Optional[Union[str, bool]] = None,
    ) -> Optional[Union[List[Dict[str, Any]], Dict[str, Any], int]]:
        """Execute MySQL query"""
        import aiomysql
        
        query, params = self.convert_query(query, params)

        async with self.pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                try:
                    if params:
                        await cursor.execute(query, params)
                    else:
                        await cursor.execute(query)

                    result: Optional[Union[List[Dict[str, Any]], Dict[str, Any], int]] = None
                    if fetch == "one":
                        result = await cursor.fetchone()
                    elif fetch == "all":
                        result = await cursor.fetchall()
                    elif fetch is False:
                        result = cursor.rowcount

                    if commit:
                        await conn.commit()
                        self.logger.debug("Committed transaction")

                    return result

                except Exception as e:
                    await conn.rollback()
                    self.logger.error(f"MySQL query execution error: {e}")
                    raise

    async def execute_many(
        self, query: str, params_list: List[Union[Tuple[Any, ...], Dict[str, Any]]], commit: bool = True
    ) -> int:
        """Execute MySQL query multiple times"""
        query, _ = self.convert_query(query)

        async with self.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                try:
                    await cursor.executemany(query, params_list)
                    rowcount = cursor.rowcount

                    if commit:
                        await conn.commit()
                        self.logger.debug(f"Committed batch transaction: {rowcount} rows affected")

                    return rowcount

                except Exception as e:
                    await conn.rollback()
                    self.logger.error(f"MySQL batch query execution error: {e}")
                    raise


class PostgreSQLBackend(BaseDatabaseBackend):
    """PostgreSQL database backend (supports both asyncpg and psycopg)"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        self.pool: Any = None  # asyncpg.Pool or AsyncConnectionPool type
        self.connection_params: Optional[Dict[str, Any]] = None
        self.driver: Optional[str] = None  # 'asyncpg' or 'psycopg'

    async def connect(self, connection_params: Dict[str, Any]) -> None:
        """Establish PostgreSQL connection pool"""
        self.connection_params = connection_params
        
        # Try asyncpg first, fall back to psycopg
        try:
            import asyncpg
            self.driver = 'asyncpg'
            self.pool = await asyncpg.create_pool(
                host=connection_params.get("host", "localhost"),
                port=connection_params.get("port", 5432),
                user=connection_params.get("user"),
                password=connection_params.get("password"),
                database=connection_params.get("database"),
                min_size=1,
                max_size=10,
            )
            self.logger.debug(f"PostgreSQL (asyncpg) connection pool established: {connection_params.get('database')}")
        except ImportError:
            # Fall back to psycopg
            from psycopg_pool import AsyncConnectionPool
            self.driver = 'psycopg'
            
            conninfo = (
                f"host={connection_params.get('host', 'localhost')} "
                f"port={connection_params.get('port', 5432)} "
                f"user={connection_params.get('user')} "
                f"password={connection_params.get('password')} "
                f"dbname={connection_params.get('database')}"
            )
            
            self.pool = AsyncConnectionPool(conninfo, min_size=1, max_size=10)
            await self.pool.wait()
            self.logger.debug(f"PostgreSQL (psycopg) connection pool established: {connection_params.get('database')}")

    async def close(self) -> None:
        """Close PostgreSQL connection pool"""
        if self.pool:
            await self.pool.close()
            self.logger.debug(f"PostgreSQL ({self.driver}) connection pool closed")

    def convert_query(self, query: str, params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None) -> Tuple[str, Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]]]:
        """Convert SQLite ? placeholders to PostgreSQL $1, $2, etc."""
        # Count the number of placeholders
        placeholder_count = query.count("?")
        
        # Replace ? with $1, $2, $3, etc.
        converted_query = query
        for i in range(1, placeholder_count + 1):
            converted_query = converted_query.replace("?", f"${i}", 1)
        
        # Convert SQLite AUTOINCREMENT to PostgreSQL SERIAL
        converted_query = re.sub(
            r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT",
            "SERIAL PRIMARY KEY",
            converted_query,
            flags=re.IGNORECASE
        )
        
        return converted_query, params

    async def execute(
        self,
        query: str,
        params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None,
        commit: bool = False,
        fetch: Optional[Union[str, bool]] = None,
    ) -> Optional[Union[List[Dict[str, Any]], Dict[str, Any], int]]:
        """Execute PostgreSQL query"""
        query, params = self.convert_query(query, params)

        if self.driver == 'asyncpg':
            return await self._execute_asyncpg(query, params, fetch)
        else:
            return await self._execute_psycopg(query, params, commit, fetch)

    async def _execute_asyncpg(
        self, 
        query: str, 
        params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]], 
        fetch: Optional[Union[str, bool]]
    ) -> Optional[Union[List[Dict[str, Any]], Dict[str, Any], int]]:
        """Execute query using asyncpg"""
        # Convert params to tuple if needed (asyncpg uses positional params)
        if isinstance(params, dict):
            # For dict params, convert to tuple of values
            params_tuple = tuple(params.values()) if params else None
        elif isinstance(params, list):
            params_tuple = tuple(params)
        else:
            params_tuple = params
            
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                try:
                    if fetch == "one":
                        if params_tuple:
                            result = await conn.fetchrow(query, *params_tuple)
                        else:
                            result = await conn.fetchrow(query)
                        return dict(result) if result else None
                    elif fetch == "all":
                        if params_tuple:
                            result = await conn.fetch(query, *params_tuple)
                        else:
                            result = await conn.fetch(query)
                        return [dict(row) for row in result]
                    elif fetch is False:
                        if params_tuple:
                            result = await conn.execute(query, *params_tuple)
                        else:
                            result = await conn.execute(query)
                        # Parse rowcount from result string like "DELETE 5"
                        match = re.search(r'\d+', str(result))
                        return int(match.group()) if match else 0
                    else:
                        if params_tuple:
                            await conn.execute(query, *params_tuple)
                        else:
                            await conn.execute(query)
                        return None

                except Exception as e:
                    self.logger.error(f"PostgreSQL (asyncpg) query execution error: {e}")
                    raise

    async def _execute_psycopg(
        self, 
        query: str, 
        params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]], 
        commit: bool, 
        fetch: Optional[Union[str, bool]]
    ) -> Optional[Union[List[Dict[str, Any]], Dict[str, Any], int]]:
        """Execute query using psycopg"""
        # Convert params to tuple if needed
        if isinstance(params, dict):
            params_tuple = tuple(params.values()) if params else None
        elif isinstance(params, list):
            params_tuple = tuple(params)
        else:
            params_tuple = params
            
        async with self.pool.connection() as conn:
            async with conn.cursor() as cursor:
                try:
                    if params_tuple:
                        await cursor.execute(query, params_tuple)
                    else:
                        await cursor.execute(query)

                    result: Optional[Union[List[Dict[str, Any]], Dict[str, Any], int]] = None
                    if fetch == "one":
                        row = await cursor.fetchone()
                        if row:
                            # Get column names
                            columns = [desc[0] for desc in cursor.description]
                            result = dict(zip(columns, row))
                    elif fetch == "all":
                        rows = await cursor.fetchall()
                        if rows:
                            columns = [desc[0] for desc in cursor.description]
                            result = [dict(zip(columns, row)) for row in rows]
                        else:
                            result = []
                    elif fetch is False:
                        result = cursor.rowcount

                    if commit:
                        await conn.commit()

                    return result

                except Exception as e:
                    await conn.rollback()
                    self.logger.error(f"PostgreSQL (psycopg) query execution error: {e}")
                    raise

    async def execute_many(
        self, query: str, params_list: List[Union[Tuple[Any, ...], Dict[str, Any]]], commit: bool = True
    ) -> int:
        """Execute PostgreSQL query multiple times"""
        query, _ = self.convert_query(query)

        if self.driver == 'asyncpg':
            async with self.pool.acquire() as conn:
                async with conn.transaction():
                    try:
                        await conn.executemany(query, params_list)
                        self.logger.debug(f"Committed batch transaction: {len(params_list)} rows affected")
                        return len(params_list)
                    except Exception as e:
                        self.logger.error(f"PostgreSQL (asyncpg) batch query execution error: {e}")
                        raise
        else:  # psycopg
            async with self.pool.connection() as conn:
                async with conn.cursor() as cursor:
                    try:
                        await cursor.executemany(query, params_list)
                        rowcount = cursor.rowcount
                        if commit:
                            await conn.commit()
                        self.logger.debug(f"Committed batch transaction: {rowcount} rows affected")
                        return rowcount
                    except Exception as e:
                        await conn.rollback()
                        self.logger.error(f"PostgreSQL (psycopg) batch query execution error: {e}")
                        raise


class MongoDBBackend(BaseDatabaseBackend):
    """MongoDB database backend"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        super().__init__(logger)
        self.client: Any = None  # AsyncIOMotorClient type
        self.db: Any = None  # AsyncIOMotorDatabase type
        self.database_name: Optional[str] = None

    async def connect(self, connection_params: Dict[str, Any]) -> None:
        """Establish MongoDB connection"""
        from motor.motor_asyncio import AsyncIOMotorClient

        self.database_name = connection_params.get("database")
        connection_string = (
            f"mongodb://{connection_params.get('user')}:{connection_params.get('password')}@"
            f"{connection_params.get('host', 'localhost')}:{connection_params.get('port', 27017)}/"
            f"{self.database_name}"
        )

        self.client = AsyncIOMotorClient(connection_string)
        self.db = self.client[self.database_name]
        
        # Verify connection
        await self.client.admin.command('ping')
        
        self.logger.debug(f"MongoDB connection established: {self.database_name}")

    async def close(self) -> None:
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self.logger.debug("MongoDB connection closed")

    def convert_query(self, query: str, params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None) -> Tuple[str, Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]]]:
        """MongoDB doesn't use SQL - this is handled in execute method"""
        return query, params

    def _parse_sql_to_mongo(self, query: str, params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Convert SQL-like query to MongoDB operation"""
        query = query.strip()
        query_upper = query.upper()
        WHERE_PATTERN = r'WHERE\s+(.+)$'

        # Extract table/collection name
        collection_match = re.search(r'(?:FROM|INTO|UPDATE)\s+(\w+)', query, re.IGNORECASE)
        collection_name = collection_match.group(1) if collection_match else None

        operation: Dict[str, Any] = {
            "collection": collection_name,
            "operation": None,
            "filter": {},
            "data": {},
            "projection": None,
        }

        # Parse SELECT
        if query_upper.startswith("SELECT"):
            operation["operation"] = "find"
            
            # Parse WHERE clause
            where_match = re.search(r'WHERE\s+(.+?)(?:ORDER BY|LIMIT)', query, re.IGNORECASE)
            if not where_match:
                # Try without ORDER BY or LIMIT
                where_match = re.search(WHERE_PATTERN, query, re.IGNORECASE)
            if where_match and params:
                where_clause = where_match.group(1).strip()
                # Only Tuple/List params supported for WHERE clauses
                if isinstance(params, (tuple, list)):
                    operation["filter"] = self._parse_where_clause(where_clause, params)
            
            # Check for LIMIT 1 (fetchone)
            if re.search(r'LIMIT\s+1', query, re.IGNORECASE):
                operation["limit"] = 1

        # Parse INSERT
        elif query_upper.startswith("INSERT"):
            operation["operation"] = "insert"
            
            # Parse column names and values
            columns_match = re.search(r'\(([^)]+)\)\s*VALUES\s*\(', query, re.IGNORECASE)
            if columns_match and params:
                columns = [col.strip() for col in columns_match.group(1).split(',')]
                # Handle both tuple/list and dict params
                if isinstance(params, dict):
                    operation["data"] = params
                else:
                    operation["data"] = dict(zip(columns, params))

        # Parse UPDATE
        elif query_upper.startswith("UPDATE"):
            operation["operation"] = "update"
            
            # Parse SET clause
            set_match = re.search(r'SET\s+(.+?)\s+WHERE', query, re.IGNORECASE)
            if set_match and params and isinstance(params, (tuple, list)):
                set_clause = set_match.group(1)
                set_parts = [s.strip() for s in set_clause.split(',')]
                
                # Build update data
                param_idx = 0
                for part in set_parts:
                    col_match = re.match(r'(\w+)\s*=', part)
                    if col_match and param_idx < len(params):
                        operation["data"][col_match.group(1)] = params[param_idx]
                        param_idx += 1
                
                # Parse WHERE clause
                where_match = re.search(WHERE_PATTERN, query, re.IGNORECASE)
                if where_match:
                    where_clause = where_match.group(1).strip()
                    remaining_params = params[param_idx:] if params else []
                    operation["filter"] = self._parse_where_clause(where_clause, remaining_params)

        # Parse DELETE
        elif query_upper.startswith("DELETE"):
            operation["operation"] = "delete"
            
            # Parse WHERE clause
            where_match = re.search(WHERE_PATTERN, query, re.IGNORECASE)
            if where_match and params:
                # Only Tuple/List params supported for WHERE clauses
                if isinstance(params, (tuple, list)):
                    where_clause = where_match.group(1).strip()
                    operation["filter"] = self._parse_where_clause(where_clause, params)

        # Parse CREATE TABLE
        elif query_upper.startswith("CREATE TABLE"):
            operation["operation"] = "create_collection"
            # MongoDB collections are created automatically

        return operation

    def _parse_where_clause(self, where_clause: str, params: Union[Tuple[Any, ...], List[Any]]) -> Dict[str, Any]:
        """Parse SQL WHERE clause to MongoDB filter"""
        filter_dict: Dict[str, Any] = {}
        
        # Simple equality: column = ?
        if '=' in where_clause and '?' in where_clause:
            parts = where_clause.split('=')
            if len(parts) == 2:
                column = parts[0].strip()
                if len(params) > 0:
                    filter_dict[column] = params[0]
        
        # Handle UNIQUE constraint (multiple columns)
        elif 'AND' in where_clause.upper():
            conditions = re.split(r'\s+AND\s+', where_clause, flags=re.IGNORECASE)
            param_idx = 0
            for condition in conditions:
                if '=' in condition:
                    column = condition.split('=')[0].strip()
                    if param_idx < len(params):
                        filter_dict[column] = params[param_idx]
                        param_idx += 1
        
        return filter_dict

    async def execute(
        self,
        query: str,
        params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None,
        commit: bool = False,
        fetch: Optional[Union[str, bool]] = None,
    ) -> Optional[Union[List[Dict[str, Any]], Dict[str, Any], int]]:
        """Execute MongoDB operation from SQL-like query"""
        try:
            operation = self._parse_sql_to_mongo(query, params)
            
            if not operation["collection"]:
                # For CREATE TABLE IF NOT EXISTS, just return success
                if "CREATE TABLE" in query.upper():
                    return None
                raise ValueError(f"Could not parse collection name from query: {query}")

            collection = self.db[operation["collection"]]

            # Execute operation
            if operation["operation"] == "find":
                cursor = collection.find(operation["filter"])
                
                if fetch == "one" or operation.get("limit") == 1:
                    result = await cursor.to_list(length=1)
                    return result[0] if result else None
                elif fetch == "all":
                    result = await cursor.to_list(length=None)
                    return result
                else:
                    return None

            elif operation["operation"] == "insert":
                result = await collection.insert_one(operation["data"])
                return result.inserted_id if fetch is False else None

            elif operation["operation"] == "update":
                result = await collection.update_many(
                    operation["filter"],
                    {"$set": operation["data"]}
                )
                return result.modified_count if fetch is False else None

            elif operation["operation"] == "delete":
                result = await collection.delete_many(operation["filter"])
                return result.deleted_count if fetch is False else None

            elif operation["operation"] == "create_collection":
                # Collections are created automatically in MongoDB
                return None

            return None

        except Exception as e:
            self.logger.error(f"MongoDB operation error: {e}")
            raise

    async def execute_many(
        self, query: str, params_list: List[Union[Tuple[Any, ...], Dict[str, Any]]], commit: bool = True
    ) -> int:
        """Execute MongoDB operation multiple times"""
        try:
            operation = self._parse_sql_to_mongo(query, params_list[0] if params_list else None)
            collection = self.db[operation["collection"]]

            if operation["operation"] == "insert":
                documents = []
                for params in params_list:
                    op = self._parse_sql_to_mongo(query, params)
                    documents.append(op["data"])
                
                result = await collection.insert_many(documents)
                return len(result.inserted_ids)

            return 0

        except Exception as e:
            self.logger.error(f"MongoDB batch operation error: {e}")
            raise


class AsyncDatabaseHandler:
    """
    Unified async database handler supporting multiple database systems.
    """

    # Backend mapping
    BACKENDS: Dict[str, Type[BaseDatabaseBackend]] = {
        "sqlite": SQLiteBackend,
        "mysql": MySQLBackend,
        "mariadb": MySQLBackend,  # MariaDB uses same backend as MySQL
        "postgresql": PostgreSQLBackend,
        "mongodb": MongoDBBackend,
    }

    def __init__(self, backend: BaseDatabaseBackend, logger: Optional[logging.Logger] = None):
        """Initialize database handler with a backend"""
        self.backend = backend
        
        if logger is None:
            self.logger = logging.getLogger("custommodules.databasehandler")
        else:
            self.logger = logger.getChild("custommodules.databasehandler")

    @classmethod
    async def create(cls, connection_string: str, logger: Optional[logging.Logger] = None) -> "AsyncDatabaseHandler":
        """
        Create and initialize a database handler from a connection string.

        Args:
            connection_string: Database connection string
            logger: Logger instance

        Returns:
            Initialized AsyncDatabaseHandler instance

        Examples:
            sqlite://path/to/db.db
            mysql://user:password@host:port/database
            postgresql://user:password@host:port/database
            mongodb://user:password@host:port/database
        """
        # Parse connection string
        parsed = urlparse(connection_string)
        db_type = parsed.scheme.lower()

        if db_type not in cls.BACKENDS:
            raise ValueError(
                f"Unsupported database type: {db_type}. "
                f"Supported types: {', '.join(cls.BACKENDS.keys())}"
            )

        # Create backend
        backend_class = cls.BACKENDS[db_type]
        backend = backend_class(logger)

        # Prepare connection parameters
        connection_params: Dict[str, Any]
        if db_type == "sqlite":
            connection_params = {"path": parsed.path.lstrip("/")}
        else:
            # Determine default port based on database type
            if db_type in ("mysql", "mariadb"):
                default_port = 3306
            elif db_type == "postgresql":
                default_port = 5432
            else:  # mongodb
                default_port = 27017
            
            connection_params = {
                "host": parsed.hostname or "localhost",
                "port": parsed.port or default_port,
                "user": parsed.username or "",
                "password": parsed.password or "",
                "database": parsed.path.lstrip("/"),
            }

        # Connect
        await backend.connect(connection_params)

        # Create handler instance
        handler = cls(backend, logger)
        handler.logger.info(f"Database handler initialized with {db_type} backend")

        return handler

    async def execute(
        self,
        query: str,
        params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None,
        commit: bool = False,
        fetch: Optional[Union[str, bool]] = None,
    ) -> Optional[Union[List[Dict[str, Any]], Dict[str, Any], int]]:
        """
        Execute a database query.

        Args:
            query: SQL query to execute (or SQL-like for MongoDB)
            params: Query parameters (optional)
            commit: Whether to commit after execution (default: False)
            fetch: Fetch mode - 'one', 'all', False (rowcount), or None

        Returns:
            Query results if fetch is specified, None otherwise
        """
        return await self.backend.execute(query, params, commit, fetch)

    async def execute_many(
        self, query: str, params_list: List[Union[Tuple[Any, ...], Dict[str, Any]]], commit: bool = True
    ) -> int:
        """
        Execute a query multiple times with different parameters.

        Args:
            query: SQL query to execute
            params_list: List of parameter tuples/dicts
            commit: Whether to commit after execution (default: True)

        Returns:
            Number of affected rows
        """
        return await self.backend.execute_many(query, params_list, commit)

    async def close(self) -> None:
        """Close database connections"""
        await self.backend.close()

    async def checkpoint_wal(self) -> None:
        """Run a WAL checkpoint (SQLite only)"""
        if isinstance(self.backend, SQLiteBackend):
            await self.backend.checkpoint_wal()
        else:
            self.logger.debug("WAL checkpoint not applicable for this database type")

    # Compatibility methods for sync usage (legacy code support)
    def close_all_connections(self) -> None:
        """Close all database connections (sync wrapper for legacy code)"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Create task but don't await (fire and forget)
                task = asyncio.create_task(self.close())
                # Prevent garbage collection warning
                task.add_done_callback(lambda t: None)
            else:
                loop.run_until_complete(self.close())
        except Exception as e:
            self.logger.error(f"Error closing connections: {e}")


class SyncDatabaseHandler:
    """
    Synchronous wrapper for AsyncDatabaseHandler to support legacy code.
    This class provides a synchronous interface that runs async operations
    in the event loop.
    
    Usage:
        db_handler = DatabaseHandler("path/to/db.db", logger)
        result = db_handler.execute("SELECT * FROM table", fetch="all")
    """
    
    def __init__(self, db_path: str, logger: Optional[logging.Logger] = None):
        """
        Initialize synchronous database handler.
        
        Args:
            db_path: Path to SQLite database file
            logger: Optional logger instance
        """
        self.db_path = db_path
        self.logger = logger or logging.getLogger(__name__)
        self._async_handler: Optional[AsyncDatabaseHandler] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        
        # Initialize the async handler synchronously
        self._initialize()
    
    def _initialize(self) -> None:
        """Initialize the async database handler"""
        try:
            # Get or create event loop
            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
            
            # Create connection string for SQLite
            connection_string = f"sqlite://{self.db_path}"
            
            # Create the async handler
            self._async_handler = self._loop.run_until_complete(
                AsyncDatabaseHandler.create(connection_string, self.logger)
            )
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database handler: {e}")
            raise
    
    def execute(
        self,
        query: str,
        params: Optional[Union[Tuple[Any, ...], List[Any], Dict[str, Any]]] = None,
        commit: bool = False,
        fetch: Optional[Union[str, bool]] = None,
    ) -> Optional[Union[List[Dict[str, Any]], Dict[str, Any], int]]:
        """
        Execute a database query synchronously.
        
        Args:
            query: SQL query to execute
            params: Query parameters (optional)
            commit: Whether to commit after execution (default: False)
            fetch: Fetch mode - 'one', 'all', False (rowcount), or None
            
        Returns:
            Query results if fetch is specified, None otherwise
        """
        if self._async_handler is None or self._loop is None:
            raise RuntimeError("Database handler not initialized")
        
        return self._loop.run_until_complete(
            self._async_handler.execute(query, params, commit, fetch)
        )
    
    def execute_many(
        self, 
        query: str, 
        params_list: List[Union[Tuple[Any, ...], Dict[str, Any]]], 
        commit: bool = True
    ) -> int:
        """
        Execute a query multiple times with different parameters.
        
        Args:
            query: SQL query to execute
            params_list: List of parameter tuples/dicts
            commit: Whether to commit after execution (default: True)
            
        Returns:
            Number of affected rows
        """
        if self._async_handler is None or self._loop is None:
            raise RuntimeError("Database handler not initialized")
        
        return self._loop.run_until_complete(
            self._async_handler.execute_many(query, params_list, commit)
        )
    
    def close_all_connections(self) -> None:
        """Close all database connections"""
        if self._async_handler and self._loop:
            try:
                self._loop.run_until_complete(self._async_handler.close())
                self.logger.debug("Database connections closed")
            except Exception as e:
                self.logger.error(f"Error closing connections: {e}")
    
    def checkpoint_wal(self) -> None:
        """Run a WAL checkpoint (SQLite only)"""
        if self._async_handler and self._loop:
            try:
                self._loop.run_until_complete(self._async_handler.checkpoint_wal())
            except Exception as e:
                self.logger.error(f"Error running WAL checkpoint: {e}")


# Alias for backwards compatibility
# Use SyncDatabaseHandler for legacy code that expects synchronous operations
DatabaseHandler = SyncDatabaseHandler

