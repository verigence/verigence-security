"""Verigence Security API route modules.

Route registration is composed explicitly by ``verigence_security.main``. Importing this package
must not mutate another router's route list; that made application composition dependent on module
import/reload order and could duplicate or lose routes in long-lived/test processes.
"""
