# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from werkzeug.exceptions import BadRequest as HTTPBadRequest
from werkzeug.exceptions import NotFound as HTTPNotFound
from werkzeug.routing import Map, Rule, Submount
from werkzeug.wrappers import Response

from oio.common.easy_value import int_value
from oio.common.exceptions import NotFound
from oio.common.json import json
from oio.common.logger import get_logger
from oio.common.wsgi import WerkzeugApp
from oio.xcute.common.backend import XcuteBackend
from oio.xcute.common.exceptions import UnknownJobTypeException
from oio.xcute.jobs import JOB_TYPES


class XcuteServer(WerkzeugApp):
    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)
        self.backend = XcuteBackend(self.conf, logger=self.logger)

        url_map = Map([
            Rule('/status', endpoint='status'),
            Submount('/v1.0/xcute', [
                Rule('/jobs', endpoint='job_list',
                     methods=['POST', 'GET']),
                Rule('/jobs/<job_id>', endpoint='job',
                     methods=['GET', 'DELETE']),
                Rule('/jobs/<job_id>/pause', endpoint='job_pause',
                     methods=['POST']),
                Rule('/jobs/<job_id>/resume', endpoint='job_resume',
                     methods=['POST']),
            ])
        ])

        super(XcuteServer, self).__init__(url_map, logger)

    def on_status(self, req):
        status = self.backend.status()
        return Response(json.dumps(status), mimetype='application/json')

    def on_job_list(self, req):
        if req.method == 'GET':
            limit = int_value(req.args.get('limit'), None)
            marker = req.args.get('marker')

            job_infos = self.backend.list_jobs(limit=limit, marker=marker)
            return Response(
                json.dumps(job_infos), mimetype='application/json')

        if req.method == 'POST':
            data = json.loads(req.data)

            job_type = data.get('type')
            if not job_type:
                raise HTTPBadRequest('Missing job type')

            job_class = JOB_TYPES.get(job_type)
            if job_class is None:
                return HTTPBadRequest(UnknownJobTypeException.message)

            # TODO: use lock
            job_config, lock = job_class.sanitize_config(
                data.get('config') or dict())

            job_id = self.backend.create(job_type, job_config)

            job_info = self.backend.get_job_info(job_id)
            return Response(
                json.dumps(job_info), mimetype='application/json', status=202)

    def on_job(self, req, job_id):
        if req.method == 'GET':
            try:
                job_info = self.backend.get_job_info(job_id)
            except NotFound as e:
                return HTTPNotFound(e.message)

            return Response(json.dumps(job_info), mimetype='application/json')

        if req.method == 'DELETE':
            self.backend.delete(job_id)

            return Response(status=204)

    def on_job_pause(self, req, job_id):
        self.backend.request_pause(job_id)

        job_info = self.backend.get_job_info(job_id)
        return Response(
            json.dumps(job_info), mimetype='application/json', status=202)

    def on_job_resume(self, req, job_id):
        self.backend.resume(job_id)

        job_info = self.backend.get_job_info(job_id)
        return Response(
            json.dumps(job_info), mimetype='application/json', status=202)


def create_app(conf):
    logger = get_logger(conf)
    app = XcuteServer(conf, logger)

    return app